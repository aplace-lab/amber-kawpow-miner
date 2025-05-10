import sys
import os
import socket
import json
import psutil
import requests
import subprocess
import threading
import logging
import webbrowser
import re
import random
import string
import time
import platform
from html import escape
from logging.handlers import RotatingFileHandler
from functools import wraps

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QCheckBox, QTreeWidget, QTreeWidgetItem,
    QDialog, QLineEdit, QFileDialog, QMessageBox, QTabWidget,
    QFormLayout, QGroupBox, QTextEdit, QComboBox,
    QStatusBar, QInputDialog
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, pyqtSlot, QSize, QObject
from PyQt6.QtGui import QIcon, QAction, QTextCursor, QPalette, QColor

from flask import Flask, request, jsonify
from flask_cors import CORS

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from ssl import SSLContext, PROTOCOL_TLS_SERVER
import datetime

# Configuration file
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    # General settings
    "CPU_PRICE_THRESHOLD": 0.4,
    "GPU_PRICE_THRESHOLD": 0.1,
    "AMBER_API_SITE_ID": "",
    "AMBER_API_KEY": "",
    "WORKER_NAME": socket.gethostname(),
    "ENABLE_IDLE_MINING": False,
    "IDLE_TIME_THRESHOLD": 300,  # Time in seconds (e.g., 5 minutes)
    "ACTIVE_PROFILE": "Default",
    "PROFILES": {
        "Default": {}
    },

    # CPU Mining settings
    "CPU_POOL_URL": "xmr-au1.nanopool.org",
    "CPU_POOL_PORT": 10343,
    "CPU_WALLET": "",
    "XMRIG_EXECUTABLE_PATH": r".\xmrig.exe",

    # Nvidia Mining settings
    "NVIDIA_ENABLED": True,
    "NVIDIA_POOL_URL": "rvn.2miners.com",
    "NVIDIA_POOL_PORT": 6060,
    "NVIDIA_WALLET": "",
    "NVIDIA_ALGORITHM": "kawpow",
    "GMINER_EXECUTABLE_PATH": r".\Gminer.exe",
    
    # AMD Mining settings
    "AMD_ENABLED": True,
    "AMD_POOL_URL": "rvn.2miners.com", 
    "AMD_POOL_PORT": 6060,
    "AMD_WALLET": "",
    "AMD_ALGORITHM": "kawpow",
    "TEAMREDMINER_EXECUTABLE_PATH": r".\teamredminer.exe",
    
    # Legacy settings (for backwards compatibility)
    "GPU_POOL_URL": "rvn.2miners.com",
    "GPU_POOL_PORT": 6060,
    "GPU_WALLET": "",
    "GPU_ALGORITHM": "kawpow",
    
    "API_AUTH_TOKEN": ""
}

# Static variables
VERSION = "0.2.6"
LOG_FILE = "amber-kawpow-miner.log"
GMINER_MINING_API_URL = "http://127.0.0.1:4068/stat"
AMD_GMINER_API_URL = "http://127.0.0.1:4069/stat"
TEAMREDMINER_API_HOST = '127.0.0.1'
TEAMREDMINER_API_PORT = 4067
EXECUTABLE_NAME = "amber-kawpow-miner.exe"
GITHUB_REPO = "aplace-lab/amber-kawpow-miner"

# Configure logging
log_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=1 * 1024 * 1024,
    backupCount=2
)
logging.basicConfig(
    handlers=[log_handler],
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS  # type: ignore
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class MinerStatsWorker(QObject):
    # Signals to emit the fetched data
    stats_fetched = pyqtSignal(float, list)

    def __init__(self, mining_processes):
        super().__init__()
        self.mining_processes = mining_processes
        self._running = True

    def stop(self):
        self._running = False

    def jsonrpc(self, ip, port, command):
        """JSON-RPC helper function for TeamRedMiner."""
        with socket.create_connection((ip, port)) as s:
            s.sendall(json.dumps(command).encode())
            response = b"".join(iter(lambda: s.recv(4096), b""))
        return json.loads(response.decode().replace('\x00', ''))

    @pyqtSlot()
    def run(self):
        while self._running:
            gpu_total_hashrate = 0.0
            devices_stats = []

            # Check for Nvidia GMiner stats
            if "gminer" in self.mining_processes:
                try:
                    summary_response = requests.get(GMINER_MINING_API_URL, timeout=5).json()

                    # Extract total hashrate information from each GPU
                    devices = summary_response.get("devices", [])
                    total_hashrate = sum(device.get("speed", 0) for device in devices)
                    gpu_total_hashrate += total_hashrate / 1e6  # Convert to MH/s

                    devices_stats.extend([
                        {
                            'name': device.get("name", "Unknown"),
                            'temperature': device.get("temperature", None),
                            'power_usage': device.get("power_usage", None),
                            'fan_speed': device.get("fan", None),
                            'hashrate': device.get("speed", 0) / 1e6  # Convert to MH/s
                        }
                        for device in devices
                    ])

                except requests.exceptions.RequestException as e:
                    logging.error(f"Controller: Error fetching Nvidia GMiner stats: {e}")
            
            # Check for AMD GMiner stats
            if "amd_gminer" in self.mining_processes:
                try:
                    summary_response = requests.get(AMD_GMINER_API_URL, timeout=5).json()

                    # Extract total hashrate information from each GPU
                    devices = summary_response.get("devices", [])
                    total_hashrate = sum(device.get("speed", 0) for device in devices)
                    gpu_total_hashrate += total_hashrate / 1e6  # Convert to MH/s

                    devices_stats.extend([
                        {
                            'name': device.get("name", "Unknown") + " (AMD)",
                            'temperature': device.get("temperature", None),
                            'power_usage': device.get("power_usage", None),
                            'fan_speed': device.get("fan", None),
                            'hashrate': device.get("speed", 0) / 1e6  # Convert to MH/s
                        }
                        for device in devices
                    ])

                except requests.exceptions.RequestException as e:
                    logging.error(f"Controller: Error fetching AMD GMiner stats: {e}")

            if "teamredminer" in self.mining_processes:
                try:
                    command = {"command": "summary+devs"}
                    response = self.jsonrpc(TEAMREDMINER_API_HOST, TEAMREDMINER_API_PORT, command)

                    # Extract summary data
                    summary = response.get('summary', {}).get('SUMMARY', [{}])[0]
                    mhs_av = summary.get('MHS av', 0)
                    gpu_total_hashrate += mhs_av

                    # Extract device data
                    devs = response.get('devs', {}).get('DEVS', [])
                    devices_stats.extend([
                        {
                            'name': dev.get('Name', f"GPU {dev.get('GPU')}"),
                            'temperature': dev.get('Temperature', None),
                            'power_usage': dev.get('GPU Power', None),
                            'fan_speed': dev.get('Fan Speed', None),
                            'hashrate': dev.get('MHS av', 0)
                        }
                        for dev in devs
                    ])

                except Exception as e:
                    logging.error(f"Controller: Error fetching TeamRedMiner stats: {e}")

            # Emit the fetched data
            self.stats_fetched.emit(gpu_total_hashrate, devices_stats)
            QThread.sleep(2)  # Sleep for 2 seconds before next fetch

class MiningControlApp(QMainWindow):
    # Define custom signals
    update_gpu_hashrate_signal = pyqtSignal(float)
    clear_gpu_stats_signal = pyqtSignal()
    update_toggle_button_state_signal = pyqtSignal()
    update_cpu_hashrate_signal = pyqtSignal(float)

    # Signals for thread-safe control
    start_mining_signal = pyqtSignal()
    stop_mining_signal = pyqtSignal()
    enable_auto_control_signal = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        logging.info("Controller: Application starting")

        self.setWindowTitle("Amber Kawpow & Monero Miner")
        self.setGeometry(100, 100, 600, 400)
        self.setMinimumSize(600, 400)
        self.setWindowIcon(QIcon(resource_path('logo.ico')))

        self.config = self.load_config()
        self.mining_processes = {}
        self.last_fetched_price = None

        # Initialize the log viewer variables
        self.log_dialog = None
        self.log_timer = None
        self.log_text_edit = None

        # Initialize hashrate values
        self.cpu_hashrate_value = 0.0
        self.gpu_hashrate_value = 0.0
        self.device_stats = []

        self.initUI()
        self.check_for_updates()
        self.monitor_conditions()
        self.update_price()
        self.validate_miner_executables()
        logging.info("Controller: Application finished loading")

        # Miner stats worker and thread
        self.miner_stats_worker = None
        self.miner_stats_thread = None

        # Connect signals to slots
        self.update_gpu_hashrate_signal.connect(self.update_gpu_hashrate)
        self.update_cpu_hashrate_signal.connect(self.update_cpu_hashrate)
        self.clear_gpu_stats_signal.connect(self.clear_gpu_stats)
        self.update_toggle_button_state_signal.connect(self.update_toggle_button_state)

        # Thread-safe control signals
        self.start_mining_signal.connect(self.start_mining)
        self.stop_mining_signal.connect(self.stop_mining)
        self.enable_auto_control_signal.connect(self.set_auto_control)

        # Initialize the Flask app
        self.api_app = Flask(__name__)
        CORS(self.api_app)
        self.api_thread = threading.Thread(target=self.run_api_server)
        self.api_thread.daemon = True
        self.api_thread.start()

    def load_config(self):
        """Load configuration from the config file, merging with defaults."""
        config = DEFAULT_CONFIG.copy()
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                try:
                    user_config = json.load(f)
                    config.update(user_config)
                except json.JSONDecodeError:
                    logging.error("Controller: Error decoding config.json, using default configuration.")
        else:
            # Generate a new API authentication token
            config["API_AUTH_TOKEN"] = self.generate_auth_token()
            # Save default config if config file doesn't exist
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)
        self.config = config
        return config

    def save_config(self):
        """Save the current configuration to a file."""
        # Make sure profiles dictionary exists
        self.config.setdefault("PROFILES", {"Default": {}})
        
        # Save current configuration to the active profile
        active_profile = self.config.get("ACTIVE_PROFILE", "Default")
        
        # Only save to profile if it's not being called during profile loading
        if hasattr(self, '_skip_profile_save') and self._skip_profile_save:
            pass
        else:
            # Core profile fields to save
            profile_fields = [
                "CPU_PRICE_THRESHOLD", "GPU_PRICE_THRESHOLD", "WORKER_NAME", 
                "ENABLE_IDLE_MINING", "IDLE_TIME_THRESHOLD",
                "CPU_POOL_URL", "CPU_POOL_PORT", "CPU_WALLET", "XMRIG_EXECUTABLE_PATH",
                "NVIDIA_ENABLED", "NVIDIA_POOL_URL", "NVIDIA_POOL_PORT", "NVIDIA_WALLET", 
                "NVIDIA_ALGORITHM", "GMINER_EXECUTABLE_PATH",
                "AMD_ENABLED", "AMD_POOL_URL", "AMD_POOL_PORT", "AMD_WALLET", 
                "AMD_ALGORITHM", "TEAMREDMINER_EXECUTABLE_PATH"
            ]
            
            # Update profile data with current settings
            for field in profile_fields:
                if field in self.config:
                    self.config["PROFILES"][active_profile][field] = self.config[field]
        
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=4)
        logging.info("Controller: Preferences saved")

    def generate_auth_token(self):
        """Generate a secure random authentication token."""
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        return token
    
    def generate_self_signed_cert(self):
        """Generate self-signed certificate for HTTPS."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.config['WORKER_NAME'])])
        
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
            .public_key(key.public_key())\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))\
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))\
            .sign(key, hashes.SHA256())

        cert_path = os.path.join(os.path.dirname(__file__), "server.crt")
        key_path = os.path.join(os.path.dirname(__file__), "server.key")
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()))
        
        return cert_path, key_path

    def initUI(self):
        """Initialize the user interface."""
        self.apply_styles()
        self.create_menu()
        self.create_main_layout()
        self.create_status_bar()

    def apply_styles(self):
        """Apply stylesheets and set the application style."""
        QApplication.setStyle("Fusion")

        # Apply a dark theme
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        QApplication.setPalette(palette)

    def create_menu(self):
        """Create the menu bar."""
        menu_bar = self.menuBar()

        # File Menu
        file_menu = menu_bar.addMenu('File')

        preferences_action = QAction('Preferences', self)
        preferences_action.setIcon(QIcon.fromTheme("preferences-system"))
        preferences_action.triggered.connect(self.open_settings)
        file_menu.addAction(preferences_action)

        logs_action = QAction('Logs', self)
        logs_action.setIcon(QIcon.fromTheme("text-x-log"))
        logs_action.triggered.connect(self.view_logs)
        file_menu.addAction(logs_action)

        file_menu.addSeparator()

        exit_action = QAction('Exit', self)
        exit_action.setIcon(QIcon.fromTheme("application-exit"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Help Menu
        help_menu = menu_bar.addMenu('Help')

        about_action = QAction('About', self)
        about_action.setIcon(QIcon.fromTheme("help-about"))
        about_action.triggered.connect(self.open_about)
        help_menu.addAction(about_action)

    def create_status_bar(self):
        """Create a status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def create_main_layout(self):
        """Create the main layout of the application."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        self.create_summary_section(main_layout)
        self.create_control_section(main_layout)
        self.create_stats_section(main_layout)

    def create_summary_section(self, layout):
        """Create the summary section."""
        summary_group = QGroupBox("Summary")
        summary_layout = QVBoxLayout()
        summary_group.setLayout(summary_layout)

        # Price and active profile info
        price_profile_layout = QHBoxLayout()
        
        self.price_label = QLabel("General Usage: $0.00/kWh")
        self.price_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        price_profile_layout.addWidget(self.price_label)
        
        summary_layout.addLayout(price_profile_layout)

        hash_rates_layout = QHBoxLayout()

        self.cpu_hashrate_label = QLabel("CPU Hashrate: N/A")
        self.cpu_hashrate_label.setStyleSheet("font-size: 14px;")
        hash_rates_layout.addWidget(self.cpu_hashrate_label)

        self.gpu_hashrate_label = QLabel("GPU Hashrate: N/A")
        self.gpu_hashrate_label.setStyleSheet("font-size: 14px;")
        hash_rates_layout.addWidget(self.gpu_hashrate_label)

        summary_layout.addLayout(hash_rates_layout)
        
        # Add algorithm and GPU type information
        info_layout = QHBoxLayout()       
        summary_layout.addLayout(info_layout)
        
        layout.addWidget(summary_group)

    def create_control_section(self, layout):
        """Create the control section."""
        control_group = QGroupBox("Mining Control")
        control_layout = QVBoxLayout()
        control_group.setLayout(control_layout)

        # Button and auto control row
        button_row = QHBoxLayout()
        
        self.toggle_btn = QPushButton("Manual Start")
        self.toggle_btn.setFixedWidth(150)
        self.toggle_btn.clicked.connect(self.toggle_mining)
        button_row.addWidget(self.toggle_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self.auto_control = QCheckBox("Auto Control Mining")
        self.auto_control.stateChanged.connect(self.update_auto_control)
        button_row.addWidget(self.auto_control, alignment=Qt.AlignmentFlag.AlignLeft)
        
        control_layout.addLayout(button_row)
        
        # Profile selector row
        profile_row = QHBoxLayout()
        
        profile_label = QLabel("Active Profile:")
        profile_row.addWidget(profile_label)
        
        self.main_profile_combo = QComboBox()
        self.main_profile_combo.addItems(self.config.get("PROFILES", {}).keys())
        current_profile = self.config.get("ACTIVE_PROFILE", "Default")
        self.main_profile_combo.setCurrentText(current_profile)
        self.main_profile_combo.currentTextChanged.connect(self.main_load_profile)
        profile_row.addWidget(self.main_profile_combo)
        
        control_layout.addLayout(profile_row)

        layout.addWidget(control_group)

    def create_stats_section(self, layout):
        """Create the statistics section."""
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout()
        stats_group.setLayout(stats_layout)

        self.stats_tree = QTreeWidget()
        self.stats_tree.setHeaderLabels(["GPU", "Temp (°C)", "Power (W)", "Fan (%)", "Hashrate (MH/s)"])
        self.stats_tree.header().setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.stats_tree)

        layout.addWidget(stats_group)

    def view_logs(self):
        """Open the log viewer."""
        if self.log_dialog is not None:
            self.log_dialog.raise_()
            return

        self.log_dialog = QMainWindow(self)
        self.log_dialog.setWindowTitle("Internal Logs")
        self.log_dialog.setGeometry(150, 150, 1000, 400)

        central_widget = QWidget()
        self.log_dialog.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)
        self.log_text_edit.setAcceptRichText(True)
        layout.addWidget(self.log_text_edit)

        # Create a timer to update logs
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.update_logs)
        self.log_timer.start(2000)  # Update every 2 seconds

        # Load initial log content
        self.update_logs()

        # Connect the window's close event
        self.log_dialog.closeEvent = self.log_dialog_closed

        self.log_dialog.show()

    def log_dialog_closed(self, event):
        """Handle the log dialog close event."""
        self.log_timer.stop()
        self.log_dialog = None
        self.log_text_edit = None
        event.accept()

    def update_logs(self):
        """Update the logs in the log viewer."""
        try:
            if self.log_text_edit is None:
                return
            with open(LOG_FILE, "r") as f:
                log_content = f.read()
                # Process the log content to add HTML formatting
                html_content = self.process_log_content(log_content)
                self.log_text_edit.setHtml(html_content)
                self.log_text_edit.moveCursor(QTextCursor.MoveOperation.End)
        except Exception as e:
            logging.error(f"Error updating logs: {e}")

    def process_log_content(self, log_content):
        """Process log content to add HTML formatting for pills."""
        # Define the mapping of keywords to their styles
        keyword_styles = {
            "Gminer": "background-color: #4CAF50; color: #ffffff; padding: 4px 8px; border-radius: 12px; font-weight: bold;",
            "TeamRedMiner": "background-color: #f44336; color: #ffffff; padding: 4px 8px; border-radius: 12px; font-weight: bold;",
            "XMRig": "background-color: #2196F3; color: #ffffff; padding: 4px 8px; border-radius: 12px; font-weight: bold;",
            "Controller": "background-color: #9E9E9E; color: #ffffff; padding: 4px 8px; border-radius: 12px; font-weight: bold;"
        }

        # Escape HTML characters to prevent rendering issues
        log_content = escape(log_content)

        # Replace keywords with styled HTML spans
        for keyword, style in keyword_styles.items():
            # Use a regex pattern to match whole words only
            pattern = r'\b{}\b:'.format(re.escape(keyword))
            replacement = f'<span style="{style}">{keyword}</span>'
            log_content = re.sub(pattern, replacement, log_content)

        # Highlight log levels
        log_content = re.sub(r'\bERROR\b', '<span style="color: red; font-weight: bold;">ERROR</span>', log_content)
        log_content = re.sub(r'\bWARNING\b', '<span style="color: orange; font-weight: bold;">WARNING</span>', log_content)
        log_content = re.sub(r'\bINFO\b', '<span style="color: green; font-weight: bold;">INFO</span>', log_content)

        # Wrap the content in <pre> to preserve formatting
        html_content = f'<pre style="font-family: monospace;">{log_content}</pre>'
        return html_content

    def open_about(self):
        """Open the about dialog."""
        QMessageBox.information(
            self, "About",
            f"<b>Amber Kawpow & Monero Miner</b><br>"
            f"Version: {VERSION}<br><br>"
            f"Developed by aplace-lab<br>"
            f"<a href='https://github.com/{GITHUB_REPO}'>GitHub Repository</a>",
            QMessageBox.StandardButton.Ok
        )

    def open_settings(self):
        """Open the settings dialog."""
        settings_dialog = QDialog(self)
        settings_dialog.setWindowTitle("Settings")
        settings_dialog.setGeometry(100, 100, 550, 400)

        layout = QVBoxLayout()
        settings_dialog.setLayout(layout)
        
        # Profile management section
        profile_group = QGroupBox("Profile Management")
        profile_layout = QHBoxLayout()
        profile_group.setLayout(profile_layout)
        
        profile_label = QLabel("Active Profile:")
        profile_layout.addWidget(profile_label)
        
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(self.config.get("PROFILES", {}).keys())
        current_profile = self.config.get("ACTIVE_PROFILE", "Default")
        self.profile_combo.setCurrentText(current_profile)
        self.profile_combo.currentTextChanged.connect(self.load_profile)
        profile_layout.addWidget(self.profile_combo)
        
        new_profile_btn = QPushButton("New")
        new_profile_btn.clicked.connect(self.create_new_profile)
        profile_layout.addWidget(new_profile_btn)
        
        rename_profile_btn = QPushButton("Rename")
        rename_profile_btn.clicked.connect(self.rename_profile)
        profile_layout.addWidget(rename_profile_btn)
        
        delete_profile_btn = QPushButton("Delete")
        delete_profile_btn.clicked.connect(self.delete_profile)
        profile_layout.addWidget(delete_profile_btn)
        
        layout.addWidget(profile_group)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        # General Tab
        general_tab = QWidget()
        general_layout = QFormLayout()
        general_tab.setLayout(general_layout)

        self.amber_site_id_entry = QLineEdit(self.config["AMBER_API_SITE_ID"])
        general_layout.addRow("Amber Site ID:", self.amber_site_id_entry)

        self.amber_api_key_entry = QLineEdit(self.config["AMBER_API_KEY"])
        general_layout.addRow("Amber API Key:", self.amber_api_key_entry)

        self.worker_name_entry = QLineEdit(self.config["WORKER_NAME"])
        general_layout.addRow("Worker Name:", self.worker_name_entry)

        self.cpu_price_threshold_entry = QLineEdit(str(self.config["CPU_PRICE_THRESHOLD"]))
        general_layout.addRow("CPU Price Threshold ($/kWh):", self.cpu_price_threshold_entry)

        self.gpu_price_threshold_entry = QLineEdit(str(self.config["GPU_PRICE_THRESHOLD"]))
        general_layout.addRow("GPU Price Threshold ($/kWh):", self.gpu_price_threshold_entry)

        self.idle_time_threshold_entry = QLineEdit(str(self.config["IDLE_TIME_THRESHOLD"]))
        general_layout.addRow("Idle Time Threshold (seconds):", self.idle_time_threshold_entry)

        self.enable_idle_mining_var = QCheckBox("Enable Idle Mining")
        self.enable_idle_mining_var.setChecked(self.config.get("ENABLE_IDLE_MINING", False))
        if platform.system() == "Windows":
            general_layout.addRow(self.enable_idle_mining_var)

        # Display the API authentication token
        api_token_layout = QHBoxLayout()
        self.api_auth_token_label = QLabel(self.config.get("API_AUTH_TOKEN", ""))
        regenerate_token_btn = QPushButton("Regenerate")
        copy_token_btn = QPushButton("Copy")
        regenerate_token_btn.clicked.connect(self.regenerate_api_token)
        copy_token_btn.clicked.connect(self.copy_api_token)
        api_token_layout.addWidget(self.api_auth_token_label)
        api_token_layout.addWidget(regenerate_token_btn)
        api_token_layout.addWidget(copy_token_btn)
        general_layout.addRow("API Auth Token:", api_token_layout)

        # CPU Tab
        cpu_tab = QWidget()
        cpu_layout = QFormLayout()
        cpu_tab.setLayout(cpu_layout)

        self.cpu_pool_url_entry = QLineEdit(self.config.get("CPU_POOL_URL", ""))
        cpu_layout.addRow("Pool URL:", self.cpu_pool_url_entry)

        self.cpu_pool_port_entry = QLineEdit(str(self.config.get("CPU_POOL_PORT", "")))
        cpu_layout.addRow("Pool Port:", self.cpu_pool_port_entry)

        self.cpu_wallet_entry = QLineEdit(self.config.get("CPU_WALLET", ""))
        cpu_layout.addRow("Wallet:", self.cpu_wallet_entry)

        # Nvidia Tab
        nvidia_tab = QWidget()
        nvidia_layout = QFormLayout()
        nvidia_tab.setLayout(nvidia_layout)
        
        self.nvidia_enabled_var = QCheckBox("Enable")
        self.nvidia_enabled_var.setChecked(self.config.get("NVIDIA_ENABLED", True))
        nvidia_layout.addRow(self.nvidia_enabled_var)
        
        self.nvidia_pool_url_entry = QLineEdit(self.config.get("NVIDIA_POOL_URL", ""))
        nvidia_layout.addRow("Pool URL:", self.nvidia_pool_url_entry)

        self.nvidia_pool_port_entry = QLineEdit(str(self.config.get("NVIDIA_POOL_PORT", "")))
        nvidia_layout.addRow("Pool Port:", self.nvidia_pool_port_entry)

        self.nvidia_wallet_entry = QLineEdit(self.config.get("NVIDIA_WALLET", ""))
        nvidia_layout.addRow("Wallet:", self.nvidia_wallet_entry)

        self.nvidia_algorithm_var = QComboBox()
        self.nvidia_algorithm_var.addItems(["kawpow", "equihash125_4"])
        self.nvidia_algorithm_var.setCurrentText(self.config.get("NVIDIA_ALGORITHM", "kawpow"))
        nvidia_layout.addRow("Mining Algorithm:", self.nvidia_algorithm_var)

        # AMD Tab
        amd_tab = QWidget()
        amd_layout = QFormLayout()
        amd_tab.setLayout(amd_layout)
        
        self.amd_enabled_var = QCheckBox("Enable")
        self.amd_enabled_var.setChecked(self.config.get("AMD_ENABLED", True))
        amd_layout.addRow(self.amd_enabled_var)
        
        self.amd_pool_url_entry = QLineEdit(self.config.get("AMD_POOL_URL", ""))
        amd_layout.addRow("Pool URL:", self.amd_pool_url_entry)

        self.amd_pool_port_entry = QLineEdit(str(self.config.get("AMD_POOL_PORT", "")))
        amd_layout.addRow("Pool Port:", self.amd_pool_port_entry)

        self.amd_wallet_entry = QLineEdit(self.config.get("AMD_WALLET", ""))
        amd_layout.addRow("Wallet:", self.amd_wallet_entry)

        self.amd_algorithm_var = QComboBox()
        self.amd_algorithm_var.addItems(["kawpow", "equihash125_4"])
        self.amd_algorithm_var.setCurrentText(self.config.get("AMD_ALGORITHM", "kawpow"))
        amd_layout.addRow("Mining Algorithm:", self.amd_algorithm_var)

        # Miners Tab (New)
        miners_tab = QWidget()
        miners_layout = QFormLayout()
        miners_tab.setLayout(miners_layout)
        
        # CPU Miner (XMRig)
        miners_layout.addRow(QLabel("<b>XMRig</b>"))
        self.xmrig_path_entry = QLineEdit(self.config["XMRIG_EXECUTABLE_PATH"])
        miners_layout.addRow("Executable Path:", self.xmrig_path_entry)
        xmrig_browse_btn = QPushButton("Browse...")
        xmrig_browse_btn.clicked.connect(self.browse_xmrig_path)
        miners_layout.addRow(xmrig_browse_btn)
        
        # Nvidia Miner (GMiner)
        miners_layout.addRow(QLabel("<b>GMiner</b>"))
        self.gminer_path_entry = QLineEdit(self.config["GMINER_EXECUTABLE_PATH"])
        miners_layout.addRow("Executable Path:", self.gminer_path_entry)
        gminer_browse_btn = QPushButton("Browse...")
        gminer_browse_btn.clicked.connect(self.browse_gminer_path)
        miners_layout.addRow(gminer_browse_btn)
        
        # AMD Miner (TeamRedMiner)
        miners_layout.addRow(QLabel("<b>TeamRedMiner</b>"))
        self.teamredminer_path_entry = QLineEdit(self.config["TEAMREDMINER_EXECUTABLE_PATH"])
        miners_layout.addRow("Executable Path:", self.teamredminer_path_entry)
        teamredminer_browse_btn = QPushButton("Browse...")
        teamredminer_browse_btn.clicked.connect(self.browse_teamredminer_path)
        miners_layout.addRow(teamredminer_browse_btn)

        # Add tabs
        tabs.addTab(general_tab, "General")
        tabs.addTab(miners_tab, "Miners")
        tabs.addTab(cpu_tab, "CPU")
        tabs.addTab(nvidia_tab, "Nvidia")
        tabs.addTab(amd_tab, "AMD")

        # Save Button
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(lambda: self.save_settings(settings_dialog))
        button_layout.addStretch()
        button_layout.addWidget(save_btn)
        layout.addLayout(button_layout)

        settings_dialog.exec()

    def copy_api_token(self):
        """Copy the API token to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.config["API_AUTH_TOKEN"])
        self.status_bar.showMessage("API token copied to clipboard", 2000)
        logging.info("Controller: API token copied to clipboard")

    def regenerate_api_token(self):
        """Regenerate the API authentication token."""
        new_token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        self.config["API_AUTH_TOKEN"] = new_token
        self.api_auth_token_label.setText(new_token)
        logging.info("Controller: API authentication token regenerated")

    def browse_xmrig_path(self):
        """Browse for XMRig executable."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select XMRig Executable", "", "Executable Files (*)")
        if file_path:
            self.xmrig_path_entry.setText(file_path)

    def browse_gminer_path(self):
        """Browse for Gminer executable."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Gminer Executable", "", "Executable Files (*)")
        if file_path:
            self.gminer_path_entry.setText(file_path)

    def browse_teamredminer_path(self):
        """Browse for TeamRedMiner executable."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select TeamRedMiner Executable", "", "Executable Files (*)")
        if file_path:
            self.teamredminer_path_entry.setText(file_path)

    def save_settings(self, dialog):
        """Save settings from the dialog."""
        # Update the config dictionary with the new settings
        self.config["CPU_PRICE_THRESHOLD"] = float(self.cpu_price_threshold_entry.text())
        self.config["GPU_PRICE_THRESHOLD"] = float(self.gpu_price_threshold_entry.text())
        self.config["AMBER_API_SITE_ID"] = self.amber_site_id_entry.text()
        self.config["AMBER_API_KEY"] = self.amber_api_key_entry.text()
        self.config["WORKER_NAME"] = self.worker_name_entry.text()
        self.config["ENABLE_IDLE_MINING"] = self.enable_idle_mining_var.isChecked()
        self.config["IDLE_TIME_THRESHOLD"] = int(self.idle_time_threshold_entry.text())

        # CPU Mining settings
        self.config["CPU_POOL_URL"] = self.cpu_pool_url_entry.text()
        self.config["CPU_POOL_PORT"] = int(self.cpu_pool_port_entry.text())
        self.config["CPU_WALLET"] = self.cpu_wallet_entry.text()
        self.config["XMRIG_EXECUTABLE_PATH"] = self.xmrig_path_entry.text()

        # Nvidia Mining settings
        self.config["NVIDIA_ENABLED"] = self.nvidia_enabled_var.isChecked()
        self.config["NVIDIA_POOL_URL"] = self.nvidia_pool_url_entry.text()
        self.config["NVIDIA_POOL_PORT"] = int(self.nvidia_pool_port_entry.text())
        self.config["NVIDIA_WALLET"] = self.nvidia_wallet_entry.text()
        self.config["NVIDIA_ALGORITHM"] = self.nvidia_algorithm_var.currentText()
        self.config["GMINER_EXECUTABLE_PATH"] = self.gminer_path_entry.text()
        
        # AMD Mining settings
        self.config["AMD_ENABLED"] = self.amd_enabled_var.isChecked()
        self.config["AMD_POOL_URL"] = self.amd_pool_url_entry.text()
        self.config["AMD_POOL_PORT"] = int(self.amd_pool_port_entry.text())
        self.config["AMD_WALLET"] = self.amd_wallet_entry.text()
        self.config["AMD_ALGORITHM"] = self.amd_algorithm_var.currentText()
        self.config["TEAMREDMINER_EXECUTABLE_PATH"] = self.teamredminer_path_entry.text()
        
        # Legacy settings (for backward compatibility)
        self.config["GPU_POOL_URL"] = self.nvidia_pool_url_entry.text()
        self.config["GPU_POOL_PORT"] = int(self.nvidia_pool_port_entry.text())
        self.config["GPU_WALLET"] = self.nvidia_wallet_entry.text()
        self.config["GPU_ALGORITHM"] = self.nvidia_algorithm_var.currentText()

        # Save current settings to the active profile
        active_profile = self.config.get("ACTIVE_PROFILE", "Default")
        self.config.setdefault("PROFILES", {})
        self.config["PROFILES"].setdefault(active_profile, {})
        
        # Update profile data with current settings
        profile_fields = [
            "CPU_PRICE_THRESHOLD", "GPU_PRICE_THRESHOLD", "WORKER_NAME", 
            "ENABLE_IDLE_MINING", "IDLE_TIME_THRESHOLD",
            "CPU_POOL_URL", "CPU_POOL_PORT", "CPU_WALLET", "XMRIG_EXECUTABLE_PATH",
            "NVIDIA_ENABLED", "NVIDIA_POOL_URL", "NVIDIA_POOL_PORT", "NVIDIA_WALLET", 
            "NVIDIA_ALGORITHM", "GMINER_EXECUTABLE_PATH",
            "AMD_ENABLED", "AMD_POOL_URL", "AMD_POOL_PORT", "AMD_WALLET", 
            "AMD_ALGORITHM", "TEAMREDMINER_EXECUTABLE_PATH"
        ]
        
        for field in profile_fields:
            self.config["PROFILES"][active_profile][field] = self.config.get(field)

        # Save the updated configuration
        self.save_config()
        dialog.close()
        self.validate_miner_executables()

    def update_auto_control(self):
        """Update auto control based on checkbox state."""
        is_checked = self.auto_control.isChecked()
        self.enable_auto_control_signal.emit(is_checked)

    @pyqtSlot(bool)
    def set_auto_control(self, enable):
        """Set auto control state."""
        self.auto_control.setChecked(enable)
        # Additional logic if needed

    def get_api_url(self):
        """Construct the Amber API URL."""
        site_id = self.config["AMBER_API_SITE_ID"]
        api_key = self.config["AMBER_API_KEY"]
        if site_id and api_key:
            return f"https://api.amber.com.au/v1/sites/{site_id}/prices/current?next=0&previous=0"
        return None

    def check_for_updates(self):
        """Check if the current version is the latest release on GitHub."""
        def worker():
            try:
                response = requests.get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest")
                response.raise_for_status()
                data = response.json()
                latest_release = data["tag_name"]
                asset = next(
                    asset for asset in data["assets"] if asset["name"] == EXECUTABLE_NAME
                )

                if latest_release > VERSION:
                    download_url = asset["browser_download_url"]
                    self.prompt_update(latest_release, download_url)
                else:
                    logging.info("Controller: Application already at latest version")

            except Exception as e:
                logging.error(f"Controller: Error checking for updates: {e}")

        threading.Thread(target=worker).start()

    def prompt_update(self, latest_release, download_url):
        """Prompt the user to update to the latest version."""
        message = f"A new version ({latest_release}) is available. Would you like to download now?"
        reply = QMessageBox.question(self, "Update Available", message,
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            webbrowser.open(download_url)

    def monitor_conditions(self):
        """Monitor conditions to control mining."""
        self.control_mining_based_on_price()
        QTimer.singleShot(1000, self.monitor_conditions)

    def fetch_electricity_price(self):
        """Fetch the current electricity price from the Amber API."""
        api_url = self.get_api_url()
        if api_url:
            headers = {
                'Authorization': f'Bearer {self.config["AMBER_API_KEY"]}',
            }
            try:
                response = requests.get(api_url, headers=headers)
                response.raise_for_status()
                data = response.json()
                for entry in data:
                    if entry['channelType'] == 'general':
                        self.last_fetched_price = entry['perKwh'] / 100  # Convert from c/kWh to $/kWh
                        return self.last_fetched_price
            except Exception as e:
                logging.error(f"Controller: Error accessing current price: {e}")
                return None
        else:
            QMessageBox.critical(self, "Configuration Error", "Amber API Site ID or API Key is missing.")
            self.open_settings()
            return None

    def control_mining_based_on_price(self):
        """Control mining based on the last fetched electricity price and idle time."""
        if self.last_fetched_price is not None:
            self.price_label.setText(f"General Usage: ${self.last_fetched_price:.2f}/kWh")

            if self.auto_control.isChecked():
                cpu_mining_active = "monero" in self.mining_processes
                gpu_mining_active = "gpu_mining" in self.mining_processes

                # Check idle time if ENABLE_IDLE_MINING is True
                idle_mining_enabled = self.config.get("ENABLE_IDLE_MINING", False)
                idle_time_threshold = int(self.config.get("IDLE_TIME_THRESHOLD", 300))
                idle_time = self.get_idle_time()

                # Determine if we should start mining based on price thresholds
                price_condition_cpu = self.last_fetched_price < self.config["CPU_PRICE_THRESHOLD"]
                price_condition_gpu = self.last_fetched_price < self.config["GPU_PRICE_THRESHOLD"]

                # Determine if idle time condition is met
                idle_condition_met = True  # Assume idle condition is met
                if idle_mining_enabled:
                    if idle_time < idle_time_threshold:
                        idle_condition_met = False

                # Decide whether to start or stop mining
                should_start_cpu_mining = price_condition_cpu and idle_condition_met
                should_start_gpu_mining = price_condition_gpu and idle_condition_met

                # Handle CPU mining
                if should_start_cpu_mining and not cpu_mining_active:
                    reasons = []
                    if price_condition_cpu:
                        reasons.append(f"Price condition met (${self.last_fetched_price:.2f}/kWh < ${self.config['CPU_PRICE_THRESHOLD']:.2f}/kWh)")
                    if idle_mining_enabled and idle_condition_met:
                        reasons.append(f"Idle time condition met ({idle_time:.2f}s >= {idle_time_threshold}s)")
                    logging.info(f"Controller: Starting CPU mining - {' and '.join(reasons)}")
                    self.start_cpu_mining()
                elif not should_start_cpu_mining and cpu_mining_active:
                    reasons = []
                    if not price_condition_cpu:
                        reasons.append(f"Price condition not met (${self.last_fetched_price:.2f}/kWh >= ${self.config['CPU_PRICE_THRESHOLD']:.2f}/kWh)")
                    if idle_mining_enabled and not idle_condition_met:
                        reasons.append(f"Idle time condition not met ({idle_time:.2f}s < {idle_time_threshold}s)")
                    logging.info(f"Controller: Stopping CPU mining - {' and '.join(reasons)}")
                    self.stop_cpu_mining()

                # Handle GPU mining
                if should_start_gpu_mining and not gpu_mining_active:
                    reasons = []
                    if price_condition_gpu:
                        reasons.append(f"Price condition met (${self.last_fetched_price:.2f}/kWh < ${self.config['GPU_PRICE_THRESHOLD']:.2f}/kWh)")
                    if idle_mining_enabled and idle_condition_met:
                        reasons.append(f"Idle time condition met ({idle_time:.2f}s >= {idle_time_threshold}s)")
                    logging.info(f"Controller: Starting GPU mining - {' and '.join(reasons)}")
                    self.start_gpu_mining()
                elif not should_start_gpu_mining and gpu_mining_active:
                    reasons = []
                    if not price_condition_gpu:
                        reasons.append(f"Price condition not met (${self.last_fetched_price:.2f}/kWh >= ${self.config['GPU_PRICE_THRESHOLD']:.2f}/kWh)")
                    if idle_mining_enabled and not idle_condition_met:
                        reasons.append(f"Idle time condition not met ({idle_time:.2f}s < {idle_time_threshold}s)")
                    logging.info(f"Controller: Stopping GPU mining - {' and '.join(reasons)}")
                    self.stop_gpu_mining()

            self.update_toggle_button_state()
        else:
            self.price_label.setText("Error retrieving price")
            logging.warning("Controller: Error retrieving price")

    def update_price(self):
        """Update the price every 5 minutes."""
        self.fetch_electricity_price()
        QTimer.singleShot(300000, self.update_price)

    def validate_miner_executables(self):
        """Validate miner executables."""
        try:
            # Validate miners based on enabled settings
            if self.config.get("NVIDIA_ENABLED", True):
                # Validate Gminer
                result = subprocess.run(
                    [self.config["GMINER_EXECUTABLE_PATH"], '--version'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                if "GMiner" in result.stdout:
                    logging.info("Controller: Gminer executable validated successfully.")
                else:
                    raise ValueError("Invalid Gminer executable output.")

            if self.config.get("AMD_ENABLED", True):
                # Validate TeamRedMiner
                result = subprocess.run(
                    [self.config["TEAMREDMINER_EXECUTABLE_PATH"], '--help'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                if "Team Red Miner" in result.stdout:
                    logging.info("Controller: TeamRedMiner executable validated successfully.")
                else:
                    raise ValueError("Invalid TeamRedMiner executable output.")

            # Validate XMRig
            result = subprocess.run(
                [self.config["XMRIG_EXECUTABLE_PATH"], '--version'],
                capture_output=True,
                text=True,
                check=True
            )
            if "XMRig" in result.stdout:
                logging.info("Controller: XMRig executable validated successfully.")
            else:
                raise ValueError("Invalid XMRig executable output.")

        except (subprocess.CalledProcessError, FileNotFoundError, ValueError) as e:
            QMessageBox.critical(self, "Validation Error", f"Failed to validate miner executables: {e}")
            logging.error(f"Validation Error: {e}")
            return False

    def toggle_mining(self):
        """Toggle mining on or off."""
        if self.is_mining_active():
            self.stop_mining()
            logging.info("Controller: Mining manually stopped")
        else:
            self.start_mining()
            logging.info("Controller: Mining manually started")

    def start_mining(self):
        """Start both CPU and GPU mining."""
        self.start_cpu_mining()
        self.start_gpu_mining()
        self.update_toggle_button_state()

    def start_cpu_mining(self):
        """Start the CPU mining process."""
        if "monero" not in self.mining_processes:
            start_cmd = [
                self.config["XMRIG_EXECUTABLE_PATH"],
                f"--url={self.config['CPU_POOL_URL']}:{self.config['CPU_POOL_PORT']}",
                "--tls",
                f"--user={self.config['CPU_WALLET']}",
                "--pass=x",
                "--coin=monero",
                "--print-time=2"
            ]
            proc = subprocess.Popen(start_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.mining_processes["monero"] = proc

            threading.Thread(target=self.monitor_monero_output, args=(proc,), daemon=True).start()
            logging.info("Controller: CPU mining started")

    def monitor_monero_output(self, proc):
        """Monitor XMRig output."""
        try:
            for line in iter(proc.stdout.readline, ''):
                if "miner    speed" in line:
                    self.update_monero_hashrate(line)
                elif len(line) > 2:
                    logging.info(f"XMRig: {line.strip()}")
            proc.stdout.close()
        finally:
            if proc.poll() is None:
                proc.wait()
            self.mining_processes.pop("monero", None)
            self.update_cpu_hashrate_signal.emit(0.0)
            self.update_toggle_button_state_signal.emit()

    def update_monero_hashrate(self, output_line):
        """Update the Monero hashrate."""
        parts = output_line.split()
        if len(parts) >= 6:
            try:
                hashrate_value = float(parts[5])
                self.update_cpu_hashrate_signal.emit(hashrate_value)
            except ValueError:
                pass

    def start_gpu_mining(self):
        """Start the GPU mining processes."""
        if "gpu_mining" not in self.mining_processes:
            self.mining_processes["gpu_mining"] = threading.Thread(target=self.run_gpu_mining)
            self.mining_processes["gpu_mining"].start()
            logging.info("Controller: GPU mining started")
            # Start the miner stats worker
            self.start_miner_stats_worker()

    def run_gpu_mining(self):
        """Run the GPU mining processes."""
        try:
            # Check for Nvidia mining
            if self.config.get("NVIDIA_ENABLED", True):
                # Start Gminer
                gminer_cmd = [
                    self.config["GMINER_EXECUTABLE_PATH"],
                    "--algo", self.config.get("NVIDIA_ALGORITHM", "kawpow"),
                    "--server", self.config["NVIDIA_POOL_URL"],
                    "--port", str(self.config["NVIDIA_POOL_PORT"]),
                    "--user", f'{self.config["NVIDIA_WALLET"]}.{self.config["WORKER_NAME"]}',
                    "--api", "4068",
                    "--nvml", "1",
                    "--cuda", "1",
                    "--opencl", "0"
                ]
                gminer_proc = subprocess.Popen(gminer_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                self.mining_processes["gminer"] = gminer_proc

                threading.Thread(target=self.monitor_gminer_output, args=(gminer_proc,), daemon=True).start()
                logging.info("Controller: Nvidia mining started")

            # Check for AMD mining
            if self.config.get("AMD_ENABLED", True):
                # Determine which miner to use based on algorithm
                amd_algorithm = self.config.get("AMD_ALGORITHM", "kawpow")
                
                if amd_algorithm == "kawpow":
                    # Use TeamRedMiner for kawpow
                    trm_cmd = [
                        self.config["TEAMREDMINER_EXECUTABLE_PATH"],
                        "-a", "kawpow",
                        "-o", f"stratum+tcp://{self.config['AMD_POOL_URL']}:{self.config['AMD_POOL_PORT']}",
                        "-u", f"{self.config['AMD_WALLET']}.{self.config['WORKER_NAME']}",
                        "-p", "x",
                        f"--api_listen={TEAMREDMINER_API_HOST}:{TEAMREDMINER_API_PORT}"
                    ]
                    trm_proc = subprocess.Popen(trm_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    self.mining_processes["teamredminer"] = trm_proc
                    threading.Thread(target=self.monitor_trm_output, args=(trm_proc,), daemon=True).start()
                    logging.info("Controller: AMD mining started with TeamRedMiner (kawpow)")
                else:
                    # Use GMiner for other algorithms with AMD-specific flags
                    amd_gminer_cmd = [
                        self.config["GMINER_EXECUTABLE_PATH"],
                        "--algo", amd_algorithm,
                        "--server", self.config["AMD_POOL_URL"],
                        "--port", str(self.config["AMD_POOL_PORT"]),
                        "--user", f'{self.config["AMD_WALLET"]}.{self.config["WORKER_NAME"]}',
                        "--api", "4069",
                        "--nvml", "0",
                        "--cuda", "0",
                        "--opencl", "1"
                    ]
                    amd_gminer_proc = subprocess.Popen(amd_gminer_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    self.mining_processes["amd_gminer"] = amd_gminer_proc
                    threading.Thread(target=self.monitor_amd_gminer_output, args=(amd_gminer_proc,), daemon=True).start()
                    logging.info(f"Controller: AMD mining started with GMiner ({amd_algorithm})")

            if "gminer" in self.mining_processes:
                self.mining_processes["gminer"].wait()
            if "amd_gminer" in self.mining_processes:
                self.mining_processes["amd_gminer"].wait()
            if "teamredminer" in self.mining_processes:
                self.mining_processes["teamredminer"].wait()

        except Exception as e:
            logging.error(f"Controller: Error in GPU mining processes: {e}")
        finally:
            self.mining_processes.pop("gminer", None)
            self.mining_processes.pop("amd_gminer", None)
            self.mining_processes.pop("teamredminer", None)
            self.mining_processes.pop("gpu_mining", None)
            # Emit signals instead of calling methods directly
            self.update_gpu_hashrate_signal.emit(0.0)
            self.clear_gpu_stats_signal.emit()
            self.update_toggle_button_state_signal.emit()
            # Stop the miner stats worker
            self.stop_miner_stats_worker()

    def monitor_gminer_output(self, proc):
        """Monitor Nvidia GMiner output."""
        try:
            for line in iter(proc.stdout.readline, ''):
                if line:
                    logging.info(f"Nvidia GMiner: {line.strip()}")
            proc.stdout.close()
        except Exception as e:
            logging.error(f"Controller: Error in Nvidia GMiner process: {e}")
        finally:
            if proc.poll() is None:
                proc.wait()
            self.mining_processes.pop("gminer", None)

    def monitor_trm_output(self, proc):
        """Monitor TeamRedMiner output."""
        try:
            for line in iter(proc.stdout.readline, ''):
                if line:
                    logging.info(f"TeamRedMiner: {line.strip()}")
            proc.stdout.close()
        except Exception as e:
            logging.error(f"Controller: Error in TeamRedMiner process: {e}")
        finally:
            if proc.poll() is None:
                proc.wait()
            self.mining_processes.pop("teamredminer", None)
            
    def monitor_amd_gminer_output(self, proc):
        """Monitor AMD GMiner output."""
        try:
            for line in iter(proc.stdout.readline, ''):
                if line:
                    logging.info(f"AMD GMiner: {line.strip()}")
            proc.stdout.close()
        except Exception as e:
            logging.error(f"Controller: Error in AMD GMiner process: {e}")
        finally:
            if proc.poll() is None:
                proc.wait()
            self.mining_processes.pop("amd_gminer", None)

    def start_miner_stats_worker(self):
        """Start the miner stats worker thread."""
        if self.miner_stats_worker is None:
            self.miner_stats_worker = MinerStatsWorker(self.mining_processes)
            self.miner_stats_thread = QThread()
            self.miner_stats_worker.moveToThread(self.miner_stats_thread)
            self.miner_stats_thread.started.connect(self.miner_stats_worker.run)
            self.miner_stats_worker.stats_fetched.connect(self.update_miner_stats)
            self.miner_stats_thread.start()

    def stop_miner_stats_worker(self):
        """Stop the miner stats worker thread."""
        if self.miner_stats_worker is not None:
            self.miner_stats_worker.stop()
            self.miner_stats_thread.quit()
            self.miner_stats_thread.wait()
            self.miner_stats_worker = None
            self.miner_stats_thread = None

    @pyqtSlot(float, list)
    def update_miner_stats(self, gpu_total_hashrate, devices_stats):
        """Update the GUI with fetched miner statistics."""
        self.gpu_hashrate_value = gpu_total_hashrate * 1e6 # Convert to H/s
        self.update_gpu_hashrate_signal.emit(self.gpu_hashrate_value)
        self.device_stats = devices_stats
        self.stats_tree.clear()

        for device in devices_stats:
            hashrate_str = f"{device['hashrate']:.2f}"
            item = QTreeWidgetItem([
                device['name'],
                str(device['temperature']) if device['temperature'] is not None else 'N/A',
                str(device['power_usage']) if device['power_usage'] is not None else 'N/A',
                str(device['fan_speed']) if device['fan_speed'] is not None else 'N/A',
                hashrate_str
            ])
            self.stats_tree.addTopLevelItem(item)

    @pyqtSlot(float)
    def update_cpu_hashrate(self, hashrate):
        """Update the CPU hashrate label."""
        self.cpu_hashrate_value = hashrate
        # Now format the label
        if hashrate > 0:
            self.cpu_hashrate_label.setText(f"CPU Hashrate: {hashrate:.2f} H/s")
        else:
            self.cpu_hashrate_label.setText("CPU Hashrate: N/A")

    @pyqtSlot(float)
    def update_gpu_hashrate(self, hashrate):
        """Update the GPU hashrate label."""
        self.gpu_hashrate_value = hashrate
        # Now format the label
        if hashrate > 0:
            hashrate_mhs = hashrate / 1e6  # Convert H/s to MH/s
            self.gpu_hashrate_label.setText(f"GPU Hashrate: {hashrate_mhs:.2f} MH/s")
        else:
            self.gpu_hashrate_label.setText("GPU Hashrate: N/A")

    @pyqtSlot()
    def clear_gpu_stats(self):
        """Clear the GPU statistics table."""
        self.stats_tree.clear()
        self.device_stats = []

    @pyqtSlot()
    def update_toggle_button_state(self):
        """Update the toggle button state based on mining activity."""
        if self.is_mining_active():
            self.toggle_btn.setText("Stop Mining")
            self.toggle_btn.setStyleSheet("background-color: red; color: white;")
        else:
            if self.auto_control.isChecked():
                if self.last_fetched_price is not None and (
                    self.last_fetched_price >= self.config["CPU_PRICE_THRESHOLD"] and self.last_fetched_price >= self.config["GPU_PRICE_THRESHOLD"]
                ):
                    self.toggle_btn.setText("Price too high")
                    self.toggle_btn.setStyleSheet("background-color: yellow; color: black;")
                elif self.config.get("ENABLE_IDLE_MINING", False) and self.get_idle_time() < int(self.config["IDLE_TIME_THRESHOLD"]):
                    self.toggle_btn.setText("Waiting on idle")
                    self.toggle_btn.setStyleSheet("background-color: orange; color: white;")
            else:
                self.toggle_btn.setText("Manual Start")
                self.toggle_btn.setStyleSheet("background-color: green; color: white;")

    def stop_mining(self):
        """Stop both GPU and CPU mining processes."""
        self.stop_cpu_mining()
        self.stop_gpu_mining()
        self.update_toggle_button_state()

    def stop_cpu_mining(self):
        """Stop the CPU mining process."""
        if "monero" in self.mining_processes:
            self._stop_mining_process("monero")
            logging.info("Controller: CPU mining stopped")

    def stop_gpu_mining(self):
        """Stop the GPU mining processes."""
        if "gminer" in self.mining_processes:
            self._stop_mining_process("gminer")
            logging.info("Controller: Nvidia GMiner mining stopped")
        if "amd_gminer" in self.mining_processes:
            self._stop_mining_process("amd_gminer")
            logging.info("Controller: AMD GMiner mining stopped")
        if "teamredminer" in self.mining_processes:
            self._stop_mining_process("teamredminer")
            logging.info("Controller: TeamRedMiner mining stopped")
        if not any(k in self.mining_processes for k in ["gminer", "amd_gminer", "teamredminer"]):
            self.stop_miner_stats_worker()

    def _stop_mining_process(self, process_key):
        """Stop a specific mining process."""
        proc = self.mining_processes.get(process_key)
        if proc and proc.poll() is None:
            logging.info(f"Controller: Killing {process_key} mining process...")
            try:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
                parent.wait()
                logging.info(f"Controller: {process_key.capitalize()} mining process terminated.")
            except Exception as e:
                logging.error(f"Controller: Error terminating {process_key} process: {e}")

        self.mining_processes.pop(process_key, None)

        if process_key == "monero":
            self.update_cpu_hashrate_signal.emit(0.0)
        elif process_key in ["gminer", "amd_gminer", "teamredminer"]:
            self.update_gpu_hashrate_signal.emit(0.0)
            self.clear_gpu_stats_signal.emit()

        self.update_toggle_button_state_signal.emit()

    def is_mining_active(self):
        """Check if any mining process is active."""
        return any(
            proc_key in self.mining_processes and self.mining_processes[proc_key].poll() is None
            for proc_key in ["monero", "gminer", "amd_gminer", "teamredminer"]
        )

    def get_idle_time(self):
        """Get the system idle time in seconds."""
        try:
            import win32api
            return (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000
        except ImportError:
            return None  # On non-Windows systems, return None

    def run_api_server(self):
        self._shutdown_event = threading.Event()
        
        @self.api_app.before_request
        def check_shutdown():
            if self._shutdown_event.is_set():
                return 'Server shutting down...', 503
            
        @self.api_app.route('/control', methods=['POST'])
        def control_mining():
            data = request.json
            command = data.get('command')
            auth = request.headers.get('Authorization')
            if auth != f"Bearer {self.config.get('API_AUTH_TOKEN')}":
                return jsonify({'error': 'Unauthorized'}), 401
            if command == 'start':
                self.start_mining_signal.emit()
                return jsonify({'status': 'Mining started'}), 200
            elif command == 'stop':
                self.stop_mining_signal.emit()
                return jsonify({'status': 'Mining stopped'}), 200
            else:
                return jsonify({'error': 'Invalid command'}), 400

        @self.api_app.route('/auto_control', methods=['POST'])
        def auto_control():
            data = request.json
            enable = data.get('enable')
            auth = request.headers.get('Authorization')
            if auth != f"Bearer {self.config.get('API_AUTH_TOKEN')}":
                return jsonify({'error': 'Unauthorized'}), 401
            if isinstance(enable, bool):
                self.enable_auto_control_signal.emit(enable)
                return jsonify({'status': f'Auto control {"enabled" if enable else "disabled"}'}), 200
            else:
                return jsonify({'error': 'Invalid value for enable'}), 400

        @self.api_app.route('/stats', methods=['GET'])
        def get_stats():
            auth = request.headers.get('Authorization')
            if auth != f"Bearer {self.config.get('API_AUTH_TOKEN')}":
                return jsonify({'error': 'Unauthorized'}), 401
            stats = {
                'timestamp': datetime.datetime.now().isoformat(),
                'worker': {
                    'name': self.config['WORKER_NAME'],
                    'version': VERSION,
                    'auto_control': self.auto_control.isChecked(),
                    'active_profile': self.config.get('ACTIVE_PROFILE', 'Default')
                },
                'power': {
                    'electricity_price': self.last_fetched_price,
                    'price_thresholds': {
                        'cpu': self.config['CPU_PRICE_THRESHOLD'],
                        'gpu': self.config['GPU_PRICE_THRESHOLD']
                    }
                },
                'mining': {
                    'cpu': {
                        'active': 'monero' in self.mining_processes,
                        'hashrate': self.cpu_hashrate_value,
                        'pool': f"{self.config['CPU_POOL_URL']}:{self.config['CPU_POOL_PORT']}"
                    },
                    'gpu': {
                        'active': any(k in self.mining_processes for k in ['gminer', 'amd_gminer', 'teamredminer']),
                        'hashrate': self.gpu_hashrate_value,
                        'nvidia': {
                            'enabled': self.config.get('NVIDIA_ENABLED', True),
                            'active': 'gminer' in self.mining_processes,
                            'algorithm': self.config.get('NVIDIA_ALGORITHM', 'kawpow'),
                            'pool': f"{self.config['NVIDIA_POOL_URL']}:{self.config['NVIDIA_POOL_PORT']}"
                        },
                        'amd': {
                            'enabled': self.config.get('AMD_ENABLED', True),
                            'active': 'teamredminer' in self.mining_processes or 'amd_gminer' in self.mining_processes,
                            'algorithm': self.config.get('AMD_ALGORITHM', 'kawpow'),
                            'using_gminer': 'amd_gminer' in self.mining_processes,
                            'pool': f"{self.config['AMD_POOL_URL']}:{self.config['AMD_POOL_PORT']}"
                        },
                        'devices': self.get_device_stats()
                    }
                },
                'profiles': list(self.config.get('PROFILES', {}).keys())
            }
            return jsonify(stats), 200
        
        @self.api_app.route('/shutdown', methods=['POST'])
        def shutdown():
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            return 'Server shutting down...'

        cert_path = os.path.join(os.path.dirname(__file__), "server.crt")
        key_path = os.path.join(os.path.dirname(__file__), "server.key")
        
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            cert_path, key_path = self.generate_self_signed_cert()
        
        context = SSLContext(PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)

        self.api_app.run(host='0.0.0.0', port=5000, ssl_context=context)

    def get_device_stats(self):
        """Return device stats with numeric values."""
        # Since self.device_stats already contains numeric values, we can return it directly
        devices = []
        for device in self.device_stats:
            devices.append({
                'name': device['name'],
                'temperature': device['temperature'],
                'power_usage': device['power_usage'],
                'fan_speed': device['fan_speed'],
                'hashrate': device['hashrate'] * 1e6  # Convert MH/s to H/s
            })
        return devices

    def closeEvent(self, event):
        """Handle the window close event."""
        self.stop_mining()
        self.stop_miner_stats_worker()
        if hasattr(self, 'api_thread'):
            def shutdown_flask():
                try:
                    requests.get('http://localhost:5000/shutdown')
                except:
                    pass
            threading.Thread(target=shutdown_flask, daemon=True).start()
            time.sleep(0.5)
        event.accept()

    def create_new_profile(self):
        """Create a new mining profile."""
        profile_name, ok = QInputDialog.getText(self, "New Profile", "Enter profile name:")
        
        if ok and profile_name:
            # Check if profile already exists
            if profile_name in self.config.get("PROFILES", {}):
                QMessageBox.warning(self, "Profile Exists", f"Profile '{profile_name}' already exists.")
                return
                
            # Create new profile with current settings
            self.config.setdefault("PROFILES", {})
            self.config["PROFILES"][profile_name] = {}
            
            # Add the new profile to the dropdowns and select it
            self.profile_combo.addItem(profile_name)
            self.profile_combo.setCurrentText(profile_name)
            self.main_profile_combo.addItem(profile_name)
            self.main_profile_combo.setCurrentText(profile_name)
            self.config["ACTIVE_PROFILE"] = profile_name
            
            logging.info(f"Controller: Created new profile '{profile_name}'")
            self.status_bar.showMessage(f"Created new profile: {profile_name}", 3000)
    
    def delete_profile(self):
        """Delete the current profile."""
        current_profile = self.profile_combo.currentText()
        
        # Don't allow deleting the Default profile
        if current_profile == "Default":
            QMessageBox.warning(self, "Cannot Delete Default", "The Default profile cannot be deleted.")
            return
            
        # Confirm deletion
        reply = QMessageBox.question(self, "Confirm Delete", 
                                    f"Are you sure you want to delete the profile '{current_profile}'?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            # Remove from config and dropdowns
            self.config["PROFILES"].pop(current_profile, None)
            
            # Get the index of the profile to remove
            index = self.profile_combo.currentIndex()
            main_index = self.main_profile_combo.findText(current_profile)
            
            # Switch to Default profile in both dropdowns
            self.profile_combo.removeItem(index)
            self.profile_combo.setCurrentText("Default")
            if main_index >= 0:
                self.main_profile_combo.removeItem(main_index)
                self.main_profile_combo.setCurrentText("Default")
            
            self.config["ACTIVE_PROFILE"] = "Default"
            
            logging.info(f"Controller: Deleted profile '{current_profile}'")
            self.status_bar.showMessage(f"Deleted profile: {current_profile}", 3000)
    
    def load_profile(self, profile_name):
        """Load settings from the selected profile in settings dialog."""
        if not profile_name or profile_name not in self.config.get("PROFILES", {}):
            return
            
        profile_data = self.config["PROFILES"].get(profile_name, {})
        self.config["ACTIVE_PROFILE"] = profile_name
        
        # Update main profile dropdown to match
        self.main_profile_combo.setCurrentText(profile_name)
        
        # Only update fields that exist in the profile
        # This allows partial profiles that only change some settings
        if profile_data:
            for key, value in profile_data.items():
                self.config[key] = value
                
            # Update UI fields to reflect profile settings
            self.update_settings_ui()
                       
            logging.info(f"Controller: Loaded profile '{profile_name}'")
            self.status_bar.showMessage(f"Loaded profile: {profile_name}", 3000)
    
    def update_settings_ui(self):
        """Update settings UI from current config."""
        # This method is called when loading a profile to update all UI fields
        # Note: This is only for the settings dialog, not the main UI
        if not hasattr(self, 'nvidia_pool_url_entry'):
            # Settings dialog not currently open
            return
            
        # Update General tab
        self.amber_site_id_entry.setText(self.config.get("AMBER_API_SITE_ID", ""))
        self.amber_api_key_entry.setText(self.config.get("AMBER_API_KEY", ""))
        self.worker_name_entry.setText(self.config.get("WORKER_NAME", ""))
        self.cpu_price_threshold_entry.setText(str(self.config.get("CPU_PRICE_THRESHOLD", 0.4)))
        self.gpu_price_threshold_entry.setText(str(self.config.get("GPU_PRICE_THRESHOLD", 0.1)))
        self.idle_time_threshold_entry.setText(str(self.config.get("IDLE_TIME_THRESHOLD", 300)))
        self.enable_idle_mining_var.setChecked(self.config.get("ENABLE_IDLE_MINING", False))
        
        # Update CPU tab
        self.cpu_pool_url_entry.setText(self.config.get("CPU_POOL_URL", ""))
        self.cpu_pool_port_entry.setText(str(self.config.get("CPU_POOL_PORT", "")))
        self.cpu_wallet_entry.setText(self.config.get("CPU_WALLET", ""))
        
        # Update Nvidia tab
        self.nvidia_enabled_var.setChecked(self.config.get("NVIDIA_ENABLED", True))
        self.nvidia_pool_url_entry.setText(self.config.get("NVIDIA_POOL_URL", ""))
        self.nvidia_pool_port_entry.setText(str(self.config.get("NVIDIA_POOL_PORT", "")))
        self.nvidia_wallet_entry.setText(self.config.get("NVIDIA_WALLET", ""))
        self.nvidia_algorithm_var.setCurrentText(self.config.get("NVIDIA_ALGORITHM", "kawpow"))
        
        # Update AMD tab
        self.amd_enabled_var.setChecked(self.config.get("AMD_ENABLED", True))
        self.amd_pool_url_entry.setText(self.config.get("AMD_POOL_URL", ""))
        self.amd_pool_port_entry.setText(str(self.config.get("AMD_POOL_PORT", "")))
        self.amd_wallet_entry.setText(self.config.get("AMD_WALLET", ""))
        self.amd_algorithm_var.setCurrentText(self.config.get("AMD_ALGORITHM", "kawpow"))
        
        # Update Miners tab
        self.xmrig_path_entry.setText(self.config.get("XMRIG_EXECUTABLE_PATH", ""))
        self.gminer_path_entry.setText(self.config.get("GMINER_EXECUTABLE_PATH", ""))
        self.teamredminer_path_entry.setText(self.config.get("TEAMREDMINER_EXECUTABLE_PATH", ""))
    
    def main_load_profile(self, profile_name):
        """Load a profile from the main UI selector."""
        if not profile_name or profile_name not in self.config.get("PROFILES", {}):
            return
            
        # Set flag to avoid overwriting the profile we're loading
        self._skip_profile_save = True
        
        try:
            profile_data = self.config["PROFILES"].get(profile_name, {})
            self.config["ACTIVE_PROFILE"] = profile_name
            
            # Only update fields that exist in the profile
            if profile_data:
                for key, value in profile_data.items():
                    self.config[key] = value
                
                # Save the configuration
                self.save_config()
                
                logging.info(f"Controller: Loaded profile '{profile_name}' from main UI")
                self.status_bar.showMessage(f"Loaded profile: {profile_name}", 3000)
        finally:
            # Remove the flag
            self._skip_profile_save = False

    def rename_profile(self):
        """Rename the currently selected profile."""
        current_profile = self.profile_combo.currentText()
        
        # Don't allow renaming the Default profile
        if current_profile == "Default":
            QMessageBox.warning(self, "Cannot Rename Default", "The Default profile cannot be renamed.")
            return
            
        # Get new name for profile
        new_name, ok = QInputDialog.getText(self, "Rename Profile", 
                                          f"Enter new name for profile '{current_profile}':",
                                          text=current_profile)
        
        if ok and new_name:
            # Check if name already exists
            if new_name in self.config.get("PROFILES", {}) and new_name != current_profile:
                QMessageBox.warning(self, "Profile Exists", f"Profile '{new_name}' already exists.")
                return
                
            # Rename the profile
            profile_data = self.config["PROFILES"].pop(current_profile)
            self.config["PROFILES"][new_name] = profile_data
            
            # Update active profile if needed
            if self.config["ACTIVE_PROFILE"] == current_profile:
                self.config["ACTIVE_PROFILE"] = new_name
                
            # Update dropdowns
            self.profile_combo.clear()
            self.profile_combo.addItems(self.config.get("PROFILES", {}).keys())
            self.profile_combo.setCurrentText(new_name)
            
            self.main_profile_combo.clear()
            self.main_profile_combo.addItems(self.config.get("PROFILES", {}).keys())
            self.main_profile_combo.setCurrentText(new_name)
            
            # Save changes
            self.save_config()
            logging.info(f"Controller: Renamed profile '{current_profile}' to '{new_name}'")
            self.status_bar.showMessage(f"Renamed profile to: {new_name}", 3000)

    def main_rename_profile(self):
        """Rename the currently selected profile from the main UI."""
        current_profile = self.main_profile_combo.currentText()
        
        # Don't allow renaming the Default profile
        if current_profile == "Default":
            QMessageBox.warning(self, "Cannot Rename Default", "The Default profile cannot be renamed.")
            return
            
        # Get new name for profile
        new_name, ok = QInputDialog.getText(self, "Rename Profile", 
                                          f"Enter new name for profile '{current_profile}':",
                                          text=current_profile)
        
        if ok and new_name:
            # Check if name already exists
            if new_name in self.config.get("PROFILES", {}) and new_name != current_profile:
                QMessageBox.warning(self, "Profile Exists", f"Profile '{new_name}' already exists.")
                return
                
            # Rename the profile
            profile_data = self.config["PROFILES"].pop(current_profile)
            self.config["PROFILES"][new_name] = profile_data
            
            # Update active profile if needed
            if self.config["ACTIVE_PROFILE"] == current_profile:
                self.config["ACTIVE_PROFILE"] = new_name
                
            # Update dropdowns
            self.main_profile_combo.clear()
            self.main_profile_combo.addItems(self.config.get("PROFILES", {}).keys())
            self.main_profile_combo.setCurrentText(new_name)
            
            # Save changes
            self.save_config()
            logging.info(f"Controller: Renamed profile '{current_profile}' to '{new_name}'")
            self.status_bar.showMessage(f"Renamed profile to: {new_name}", 3000)

def main():
    app = QApplication(sys.argv)
    window = MiningControlApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
