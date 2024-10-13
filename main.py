import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, Toplevel, filedialog, END, BOTH, X, W, E, TOP
import requests
import subprocess
import threading
import psutil
import socket
import json
import sys
import os
import win32api
import webbrowser
import logging
from logging.handlers import RotatingFileHandler 

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
    
    # CPU Mining settings
    "CPU_POOL_URL": "xmr-au1.nanopool.org",
    "CPU_POOL_PORT": 10343,
    "CPU_WALLET": "",
    "XMRIG_EXECUTABLE_PATH": r".\xmrig.exe",

    # GPU Mining settings
    "GPU_POOL_URL": "rvn.2miners.com",
    "GPU_POOL_PORT": 6060,
    "GPU_WALLET": "",
    "GPU_TYPE": "Nvidia+AMD",
    "GMINER_EXECUTABLE_PATH": r".\Gminer.exe",
    "TEAMREDMINER_EXECUTABLE_PATH": r".\teamredminer.exe"
}

# Static variables
VERSION = "0.2.1"
LOG_FILE = "amber-kawpow-miner.log"
GMINER_MINING_API_URL = "http://127.0.0.1:4068/stat"
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
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class MiningControlApp:
    def __init__(self, root):
        logging.info("Controller: Application starting")
        self.root = root
        self.root.title("Amber Kawpow & Monero Miner")
        self.root.geometry("650x500")
        self.root.resizable(False, False)

        self.config = self.load_config()
        self.mining_processes = {}  # To keep track of subprocesses
        self.last_fetched_price = None

        self.create_menu()          # Create the menu bar
        self.create_main_frame()
        self.create_summary_section()
        self.create_control_section()
        self.create_stats_section()

        self.check_for_updates()    # Check for updates
        self.monitor_conditions()   # Start monitoring idle time and price thresholds
        self.update_price()         # Start fetching the electricity price every 5 minutes
        logging.info("Controller: Application finished loading")

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)  # Handle window close event

    def load_config(self):
        """Load configuration from the config file, merging with defaults."""
        config = DEFAULT_CONFIG.copy()
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                user_config = json.load(f)
                config.update(user_config)
        else:
            # Save default config if config file doesn't exist
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)
        return config

    def save_config(self):
        """Save the current configuration to a file."""
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=4)
        logging.info("Controller: Preferences saved")

    def create_menu(self):
        """Create a custom menu bar using a Frame."""
        menu_frame = ttk.Frame(self.root, padding=(5, 2))
        menu_frame.pack(fill=X, side=TOP)

        file_menu_button = ttk.Menubutton(menu_frame, text="File", bootstyle="dark", direction=RIGHT)
        file_menu = ttk.Menu(file_menu_button, tearoff=0)
        file_menu.add_command(label="Preferences", command=self.open_settings)
        file_menu.add_command(label="About", command=self.open_about)
        file_menu.add_command(label="Logs", command=self.view_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        file_menu_button.config(menu=file_menu)
        file_menu_button.pack(side='left')

    def view_logs(self):
        """Open the log file in a simple text viewer with auto scroll functionality."""
        try:
            log_window = Toplevel(self.root)
            log_window.title("Internal Logs")
            log_window.geometry("600x400")
            log_window.resizable(True, True)

            # Create a frame to hold the text widget and scrollbar together
            log_frame = ttk.Frame(log_window)
            log_frame.pack(fill=BOTH, expand=True)

            text_widget = ttk.Text(log_frame, wrap="none")
            text_widget.config(state="disabled")  # Make the text read-only
            text_widget.grid(row=0, column=0, sticky="nsew")

            # Add a scrollbar
            scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=text_widget.yview)
            text_widget.configure(yscrollcommand=scrollbar.set)
            scrollbar.grid(row=0, column=1, sticky="ns")

            # Configure grid weights to allow resizing
            log_frame.grid_rowconfigure(0, weight=1)
            log_frame.grid_columnconfigure(0, weight=1)

            # Method to update the logs with auto-scroll
            def update_logs():
                try:
                    with open(LOG_FILE, "r") as file:
                        log_content = file.read()

                    text_widget.config(state="normal")  # Enable editing temporarily
                    text_widget.delete("1.0", END)  # Clear the current content
                    text_widget.insert("1.0", log_content)  # Insert updated content
                    text_widget.see(END)  # Scroll to the end
                    text_widget.config(state="disabled")  # Disable editing again

                    # Call this method every 2 seconds to update the logs dynamically
                    log_window.after(2000, update_logs)

                except Exception as e:
                    messagebox.showerror("Error", f"Unable to open log file: {e}")

            # Start the first log update
            update_logs()

        except Exception as e:
            messagebox.showerror("Error", f"Unable to open log file: {e}")

    def create_main_frame(self):
        """Create the main frame for the application."""
        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(fill=BOTH, expand=True)

    def create_summary_section(self):
        """Create the summary information section."""
        summary_frame = ttk.Labelframe(self.main_frame, text="Summary", padding=(10, 10))
        summary_frame.pack(fill=X, pady=(0, 10))

        self.price_label = ttk.Label(summary_frame, text="General Usage: $0.00/kWh", font="-size 12")
        self.price_label.pack(anchor=W)

        self.cpu_hashrate_label = ttk.Label(summary_frame, text="CPU Hashrate: N/A", font="-size 12")
        self.cpu_hashrate_label.pack(anchor=W)

        self.gpu_hashrate_label = ttk.Label(summary_frame, text="GPU Hashrate: N/A", font="-size 12")
        self.gpu_hashrate_label.pack(anchor=W)

    def create_control_section(self):
        """Create the mining control section."""
        control_frame = ttk.Labelframe(self.main_frame, text="Mining Control", padding=(10, 10))
        control_frame.pack(fill=X, pady=(0, 10))

        self.toggle_btn = ttk.Button(control_frame, text="Manual Start", command=self.toggle_mining, bootstyle="primary", width=15)
        self.toggle_btn.pack(pady=(0, 5))

        self.auto_control = ttk.IntVar()
        self.auto_control_check = ttk.Checkbutton(
            control_frame,
            text="Auto Control Mining",
            variable=self.auto_control,
            bootstyle="round-toggle",
            command=self.update_price  # Trigger update_price on value change
        )
        self.auto_control_check.pack(anchor=W, pady=(10, 0))

    def create_stats_section(self):
        """Create the statistics section."""
        stats_frame = ttk.Labelframe(self.main_frame, text="Statistics", padding=(10, 10))
        stats_frame.pack(fill=BOTH, expand=True, pady=(0, 10))

        self.stats_tree = ttk.Treeview(stats_frame, columns=("gpu", "temp", "power", "fan", "hashrate"), show='headings', height=10)
        self.stats_tree.pack(fill=BOTH, expand=True)

        self.stats_tree.heading("gpu", text="GPU")
        self.stats_tree.heading("temp", text="Temp (°C)")
        self.stats_tree.heading("power", text="Power (W)")
        self.stats_tree.heading("fan", text="Fan (%)")
        self.stats_tree.heading("hashrate", text="Hashrate (MH/s)")

        self.stats_tree.column("gpu", width=100, anchor="w")
        self.stats_tree.column("temp", width=25, anchor="center")
        self.stats_tree.column("power", width=25, anchor="center")
        self.stats_tree.column("fan", width=25, anchor="center")
        self.stats_tree.column("hashrate", width=25, anchor="center")

    def open_about(self):
        """Open the about window."""
        settings_window = Toplevel(self.root)
        settings_window.title("About")
        settings_window.geometry("400x200")
        settings_window.resizable(False, False)

        information_frame = ttk.Labelframe(settings_window, text="Information", padding=(10, 10))
        information_frame.pack(fill=X, pady=(0, 10))

        about_label = ttk.Label(information_frame, text=f"Version: {VERSION}", font="-size 10")
        about_label.pack(anchor=W)

    def open_settings(self):
        """Open the settings window."""
        settings_window = Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x600")
        settings_window.resizable(False, False)

        # Create a Notebook (tabbed interface)
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill=BOTH, expand=True)

        # Create tabs
        general_frame = ttk.Frame(notebook, padding=10)
        cpu_frame = ttk.Frame(notebook, padding=10)
        gpu_frame = ttk.Frame(notebook, padding=10)

        notebook.add(general_frame, text="General")
        notebook.add(cpu_frame, text="CPU")
        notebook.add(gpu_frame, text="GPU")

        # General settings
        self.add_setting_field(general_frame, "Amber Site ID:", self.config["AMBER_API_SITE_ID"], "amber_site_id_entry")
        self.add_setting_field(general_frame, "Amber API Key:", self.config["AMBER_API_KEY"], "amber_api_key_entry")
        self.add_setting_field(general_frame, "Worker Name:", self.config["WORKER_NAME"], "worker_name_entry")
        self.add_setting_field(general_frame, "CPU Electricity Cost Threshold ($/kWh):", self.config["CPU_PRICE_THRESHOLD"], "cpu_price_threshold_entry")
        self.add_setting_field(general_frame, "GPU Electricity Cost Threshold ($/kWh):", self.config["GPU_PRICE_THRESHOLD"], "gpu_price_threshold_entry")
        self.add_setting_field(general_frame, "Idle Time Threshold (seconds):", self.config["IDLE_TIME_THRESHOLD"], "idle_time_threshold_entry")

        self.enable_idle_mining_var = ttk.IntVar(value=int(self.config.get("ENABLE_IDLE_MINING", 0)))
        self.enable_idle_mining = ttk.Checkbutton(
            general_frame,
            text="Enable Idle Mining",
            variable=self.enable_idle_mining_var,
            bootstyle="round-toggle"
        )
        self.enable_idle_mining.pack(anchor=W, pady=(10, 0))

        # CPU Mining settings
        self.add_setting_field(cpu_frame, "Pool URL:", self.config.get("CPU_POOL_URL", ""), "cpu_pool_url_entry")
        self.add_setting_field(cpu_frame, "Pool Port:", str(self.config.get("CPU_POOL_PORT", "")), "cpu_pool_port_entry")
        self.add_setting_field(cpu_frame, "Wallet:", self.config.get("CPU_WALLET", ""), "cpu_wallet_entry")
        self.add_setting_field(cpu_frame, "XMRig Executable Path:", self.config["XMRIG_EXECUTABLE_PATH"], "xmrig_path_entry")
        self.create_browse_xmr_button(cpu_frame)

        # GPU Mining settings
        self.add_setting_field(gpu_frame, "Pool URL:", self.config.get("GPU_POOL_URL", ""), "gpu_pool_url_entry")
        self.add_setting_field(gpu_frame, "Pool Port:", str(self.config.get("GPU_POOL_PORT", "")), "gpu_pool_port_entry")
        self.add_setting_field(gpu_frame, "Wallet:", self.config.get("GPU_WALLET", ""), "gpu_wallet_entry")

        # GPU Type dropdown
        ttk.Label(gpu_frame, text="GPU Type:").pack(anchor=W, padx=10, pady=5)
        self.gpu_type_var = ttk.StringVar(value=self.config.get("GPU_TYPE", "Nvidia+AMD"))
        self.gpu_type_dropdown = ttk.Combobox(
            gpu_frame,
            textvariable=self.gpu_type_var,
            values=["Nvidia", "Nvidia+AMD", "AMD"],
            state="readonly"
        )
        self.gpu_type_dropdown.pack(fill=X, padx=10, pady=5)

        self.add_setting_field(gpu_frame, "Gminer Executable Path:", self.config["GMINER_EXECUTABLE_PATH"], "gminer_path_entry")
        self.create_browse_gminer_button(gpu_frame)
        self.add_setting_field(gpu_frame, "TeamRedMiner Executable Path:", self.config["TEAMREDMINER_EXECUTABLE_PATH"], "teamredminer_path_entry")
        self.create_browse_teamredminer_button(gpu_frame)

        # Save button
        self.create_save_button(settings_window)

    def add_setting_field(self, window, label_text, default_value, entry_var_name):
        """Helper method to add a labeled input field to the settings window."""
        ttk.Label(window, text=label_text).pack(anchor=W, padx=10, pady=5)
        entry = ttk.Entry(window)
        entry.insert(0, default_value)
        entry.pack(fill=X, padx=10, pady=5)
        setattr(self, entry_var_name, entry)

    def create_browse_gminer_button(self, window):
        """Create a button for browsing the Gminer executable."""
        browse_button = ttk.Button(window, text="Browse...", command=self.browse_gminer_path)
        browse_button.pack(anchor=E, padx=10, pady=5)

    def create_browse_teamredminer_button(self, window):
        """Create a button for browsing the TeamRedMiner executable."""
        browse_button = ttk.Button(window, text="Browse...", command=self.browse_teamredminer_path)
        browse_button.pack(anchor=E, padx=10, pady=5)

    def create_browse_xmr_button(self, window):
        """Create a button for browsing the XMRig executable."""
        browse_button = ttk.Button(window, text="Browse...", command=self.browse_xmrig_path)
        browse_button.pack(anchor=E, padx=10, pady=5)

    def create_save_button(self, window):
        """Create a button for saving settings."""
        save_button = ttk.Button(window, text="Save", command=lambda: self.save_settings(window))
        save_button.pack(anchor=E, padx=10, pady=20)

    def browse_gminer_path(self):
        """Open a file dialog to browse for the Gminer executable."""
        file_path = filedialog.askopenfilename(title="Select Gminer Executable", filetypes=[("Executable Files", "*.exe")])
        if file_path:
            self.gminer_path_entry.delete(0, END)
            self.gminer_path_entry.insert(0, file_path)

    def browse_teamredminer_path(self):
        """Open a file dialog to browse for the TeamRedMiner executable."""
        file_path = filedialog.askopenfilename(title="Select TeamRedMiner Executable", filetypes=[("Executable Files", "*.exe")])
        if file_path:
            self.teamredminer_path_entry.delete(0, END)
            self.teamredminer_path_entry.insert(0, file_path)

    def browse_xmrig_path(self):
        """Open a file dialog to browse for the XMRig executable."""
        file_path = filedialog.askopenfilename(title="Select XMRig Executable", filetypes=[("Executable Files", "*.exe")])
        if file_path:
            self.xmrig_path_entry.delete(0, END)
            self.xmrig_path_entry.insert(0, file_path)

    def save_settings(self, settings_window):
        """Save the settings from the input fields."""
        # Update the config dictionary with the new settings
        self.config["CPU_PRICE_THRESHOLD"] = float(self.cpu_price_threshold_entry.get())
        self.config["GPU_PRICE_THRESHOLD"] = float(self.gpu_price_threshold_entry.get())
        self.config["AMBER_API_SITE_ID"] = self.amber_site_id_entry.get()
        self.config["AMBER_API_KEY"] = self.amber_api_key_entry.get()
        self.config["WORKER_NAME"] = self.worker_name_entry.get()
        self.config["ENABLE_IDLE_MINING"] = bool(self.enable_idle_mining_var.get())
        self.config["IDLE_TIME_THRESHOLD"] = int(self.idle_time_threshold_entry.get())

        # CPU Mining settings
        self.config["CPU_POOL_URL"] = self.cpu_pool_url_entry.get()
        self.config["CPU_POOL_PORT"] = int(self.cpu_pool_port_entry.get())
        self.config["CPU_WALLET"] = self.cpu_wallet_entry.get()
        self.config["XMRIG_EXECUTABLE_PATH"] = self.xmrig_path_entry.get()

        # GPU Mining settings
        self.config["GPU_POOL_URL"] = self.gpu_pool_url_entry.get()
        self.config["GPU_POOL_PORT"] = int(self.gpu_pool_port_entry.get())
        self.config["GPU_WALLET"] = self.gpu_wallet_entry.get()
        self.config["GPU_TYPE"] = self.gpu_type_var.get()  # Save GPU Type
        self.config["GMINER_EXECUTABLE_PATH"] = self.gminer_path_entry.get()
        self.config["TEAMREDMINER_EXECUTABLE_PATH"] = self.teamredminer_path_entry.get()

        # Save the updated configuration
        self.save_config()

        # Reload the configuration to apply changes immediately
        settings_window.destroy()
        self.validate_miner_executables()  # Validate miner executables after settings change

    def get_api_url(self):
        """Construct the Amber API URL based on the site ID and API key."""
        site_id = self.config["AMBER_API_SITE_ID"]
        api_key = self.config["AMBER_API_KEY"]
        if site_id and api_key:
            return f"https://api.amber.com.au/v1/sites/{site_id}/prices/current?next=0&previous=0"
        return None

    def check_for_updates(self):
        """Check if the current version is the latest release on GitHub."""
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

    def prompt_update(self, latest_release, download_url):
        """Prompt the user to update to the latest version and download the new executable."""
        message = f"A new version ({latest_release}) is available. Would you like to download now?"
        response = messagebox.askokcancel("Update Available", message)

        if response:
            webbrowser.open(download_url)

    def get_idle_time(self):
        """Get the system idle time in seconds."""
        return (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000

    def monitor_conditions(self):
        """Monitor idle time and price conditions to control mining."""
        if self.config.get("ENABLE_IDLE_MINING", False):
            idle_time = self.get_idle_time()
            idle_threshold = int(self.config["IDLE_TIME_THRESHOLD"])

            if idle_time >= idle_threshold:
                self.control_mining_based_on_price()
            else:
                self.stop_mining()
        else:
            self.control_mining_based_on_price()

        self.root.after(1000, self.monitor_conditions)

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
            messagebox.showerror("Configuration Error", "Amber API Site ID or API Key is missing.")
            self.open_settings()
            return None

    def control_mining_based_on_price(self):
        """Control mining based on the last fetched electricity price."""
        if self.last_fetched_price is not None:
            self.price_label.config(text=f"General Usage: ${self.last_fetched_price:.2f}/kWh")

            if self.auto_control.get() == 1:
                cpu_mining_active = "monero" in self.mining_processes
                gpu_mining_active = "gpu_mining" in self.mining_processes

                # Handle CPU mining based on price threshold
                if self.last_fetched_price < self.config["CPU_PRICE_THRESHOLD"] and not cpu_mining_active:
                    logging.info(f"Controller: Electricity cost below threshold ({self.last_fetched_price} < {self.config['CPU_PRICE_THRESHOLD']})")
                    self.start_cpu_mining()
                elif self.last_fetched_price >= self.config["CPU_PRICE_THRESHOLD"] and cpu_mining_active:
                    logging.info(f"Controller: Electricity cost above threshold ({self.last_fetched_price} > {self.config['CPU_PRICE_THRESHOLD']})")
                    self.stop_cpu_mining()

                # Handle GPU mining based on price threshold
                if self.last_fetched_price < self.config["GPU_PRICE_THRESHOLD"] and not gpu_mining_active:
                    logging.info(f"Controller: Electricity cost below threshold ({self.last_fetched_price} < {self.config['GPU_PRICE_THRESHOLD']})")
                    self.start_gpu_mining()
                elif self.last_fetched_price >= self.config["GPU_PRICE_THRESHOLD"] and gpu_mining_active:
                    logging.info(f"Controller: Electricity cost above threshold ({self.last_fetched_price} > {self.config['GPU_PRICE_THRESHOLD']})")
                    self.stop_gpu_mining()

            self.update_toggle_button_state()  # Update button state after managing the mining processes
        else:
            self.price_label.config(text="Error retrieving price")
            logging.warning("Error retrieving price")

    def update_price(self):
        """Update the price every 5 minutes by fetching it from the API."""
        self.fetch_electricity_price()
        self.root.after(300000, self.update_price)  # Update every 5 minutes

    def validate_miner_executables(self):
        """Validate the miner executables by checking their versions."""
        try:
            # Validate miners based on GPU_TYPE
            gpu_type = self.config.get("GPU_TYPE", "Nvidia+AMD")
            if gpu_type in ["Nvidia", "Nvidia+AMD"]:
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

            if gpu_type in ["AMD", "Nvidia+AMD"]:
                # Validate TeamRedMiner
                result = subprocess.run(
                    [self.config["TEAMREDMINER_EXECUTABLE_PATH"], '--version'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                if "Team Red Miner version" in result.stdout or "TeamRedMiner" in result.stdout:
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
            messagebox.showerror("Validation Error", f"Failed to validate miner executables: {e}")
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
        """Start both GPU (Kawpow) and CPU (Monero) mining processes."""
        self.start_cpu_mining()
        self.start_gpu_mining()

        # Update button state after starting mining
        self.update_toggle_button_state()

    def start_cpu_mining(self):
        """Start the CPU (Monero) mining process."""
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
            self.mining_processes["monero"] = proc  # Only track this subprocess
            
            # Run the monitoring of the subprocess output in a separate thread
            threading.Thread(target=self.monitor_monero_output, args=(proc,), daemon=True).start()
            logging.info("Controller: CPU mining started")

    def monitor_monero_output(self, proc):
        """Monitor XMRig output and log it to file."""
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
            # Remove the process from tracking once it's done
            self.mining_processes.pop("monero", None)
            self.update_cpu_hashrate("N/A")
            self.update_toggle_button_state()  # Ensure the button state is updated when the miner stops

    def update_monero_hashrate(self, output_line):
        """Update the Monero hashrate based on the XMRig output."""
        # Example line: [2024-09-02 23:49:05.795]  miner    speed 10s/60s/15m 7359.2 n/a n/a H/s max 7373.7 H/s
        parts = output_line.split()
        if len(parts) >= 6:
            hashrate = f"{parts[5]} H/s"
            self.update_cpu_hashrate(hashrate)

    def start_gpu_mining(self):
        """Start the GPU mining processes based on GPU_TYPE."""
        if "gpu_mining" not in self.mining_processes:
            self.mining_processes["gpu_mining"] = threading.Thread(target=self.run_gpu_mining)
            self.mining_processes["gpu_mining"].start()
            logging.info("Controller: GPU mining started")

    def run_gpu_mining(self):
        """Run the GPU mining processes based on GPU_TYPE."""
        try:
            gpu_type = self.config.get("GPU_TYPE", "Nvidia+AMD")
            if gpu_type in ["Nvidia", "Nvidia+AMD"]:
                # Start Gminer
                gminer_cmd = [
                    self.config["GMINER_EXECUTABLE_PATH"],
                    "--algo", "kawpow",
                    "--server", self.config["GPU_POOL_URL"],
                    "--port", str(self.config["GPU_POOL_PORT"]),
                    "--user", self.config["GPU_WALLET"],
                    "--worker", self.config["WORKER_NAME"],
                    "--api", "4068",
                    "--nvml", "1", 
                    "--cuda", "1", 
                    "--opencl", "0"
                ]
                gminer_proc = subprocess.Popen(gminer_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                self.mining_processes["gminer"] = gminer_proc

                threading.Thread(target=self.monitor_gminer_output, args=(gminer_proc,), daemon=True).start()

            if gpu_type in ["AMD", "Nvidia+AMD"]:
                # Start TeamRedMiner
                trm_cmd = [
                    self.config["TEAMREDMINER_EXECUTABLE_PATH"],
                    "-a", "kawpow",
                    "-o", f"stratum+tcp://{self.config['GPU_POOL_URL']}:{self.config['GPU_POOL_PORT']}",
                    "-u", f"{self.config['GPU_WALLET']}.{self.config['WORKER_NAME']}",
                    "-p", "x",
                    f"--api_listen={TEAMREDMINER_API_HOST}:{TEAMREDMINER_API_PORT}"
                ]
                trm_proc = subprocess.Popen(trm_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                self.mining_processes["teamredminer"] = trm_proc

                threading.Thread(target=self.monitor_trm_output, args=(trm_proc,), daemon=True).start()

            self.update_miner_stats()  # Start stats updating

            # Wait for miners to finish
            if "gminer" in self.mining_processes:
                self.mining_processes["gminer"].wait()
            if "teamredminer" in self.mining_processes:
                self.mining_processes["teamredminer"].wait()

        except Exception as e:
            logging.error(f"Controller: Error in GPU mining processes: {e}")
        finally:
            self.mining_processes.pop("gminer", None)
            self.mining_processes.pop("teamredminer", None)
            self.mining_processes.pop("gpu_mining", None)
            self.update_gpu_hashrate("N/A")
            self.clear_gpu_stats()
            self.update_toggle_button_state()  # Ensure the button state is updated after the miner stops

    def monitor_gminer_output(self, proc):
        """Monitor Gminer output and log it to file."""
        try:
            for line in iter(proc.stdout.readline, ''):
                if line:
                    logging.info(f"Gminer: {line.strip()}")
            proc.stdout.close()
        except Exception as e:
            logging.error(f"Controller: Error in Gminer process: {e}")
        finally:
            if proc.poll() is None:
                proc.wait()
            self.mining_processes.pop("gminer", None)
            self.update_miner_stats()

    def monitor_trm_output(self, proc):
        """Monitor TeamRedMiner output and log it to file."""
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
            self.update_miner_stats()

    def jsonrpc(self, ip, port, command):
        """JSON-RPC helper function for TeamRedMiner."""
        with socket.create_connection((ip, port)) as s:
            s.sendall(json.dumps(command).encode())
            response = b"".join(iter(lambda: s.recv(4096), b""))
        return json.loads(response.decode().replace('\x00', ''))

    def update_miner_stats(self):
        """Fetch and update miner statistics from both miners."""
        gpu_total_hashrate = 0.0
        self.clear_gpu_stats()

        if "gminer" in self.mining_processes:
            try:
                summary_response = requests.get(GMINER_MINING_API_URL, timeout=5).json()
                
                # Extract total hashrate information from each GPU
                devices = summary_response.get("devices", [])
                total_hashrate = sum(device.get("speed", 0) for device in devices)
                gpu_total_hashrate += total_hashrate / 1e6  # Convert to MH/s

                # Populate stats for each device
                self.populate_gminer_stats(devices)
                
            except requests.exceptions.RequestException as e:
                logging.error(f"Controller: Error fetching Gminer stats: {e}")

        # Get stats from TeamRedMiner
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
                self.populate_trm_stats(devs)

            except Exception as e:
                logging.error(f"Controller: Error fetching TeamRedMiner stats: {e}")

        # Update combined GPU hashrate
        self.update_gpu_hashrate(f"{gpu_total_hashrate:.2f} MH/s")

        # Repeat every 2 seconds while mining
        if "gminer" in self.mining_processes or "teamredminer" in self.mining_processes:
            self.root.after(2000, self.update_miner_stats)

    def update_cpu_hashrate(self, hashrate):
        """Update the CPU hashrate label."""
        self.cpu_hashrate_label.config(text=f"CPU Hashrate: {hashrate}")

    def populate_gminer_stats(self, devices):
        """Populate the GPU statistics table with Gminer data."""
        logging.error(devices)
        for gpu_stats in devices:
            gpu_name = gpu_stats.get("name", "Unknown")
            gpu_temp = gpu_stats.get("temperature", "N/A")
            power_usage = gpu_stats.get("power_usage", "N/A")
            fan_speed = gpu_stats.get("fan", "N/A")
            gpu_hashrate = gpu_stats.get("speed", 0) / 1e6  # Convert to MH/s

            self.stats_tree.insert("", "end", values=(gpu_name, gpu_temp, power_usage, fan_speed, f"{gpu_hashrate:.2f}"))

    def populate_trm_stats(self, devs):
        """Populate the GPU statistics table with TeamRedMiner data."""
        for gpu_stats in devs:
            gpu_id = gpu_stats.get('GPU')
            gpu_name = gpu_stats.get('Name', f"GPU {gpu_id}")
            gpu_temp = gpu_stats.get('Temperature', 'N/A')
            fan_speed = gpu_stats.get('Fan Speed', 'N/A')
            power_usage = gpu_stats.get('GPU Power', 'N/A')
            mhs_av = gpu_stats.get('MHS av', 0)

            self.stats_tree.insert("", "end", values=(gpu_name, gpu_temp, power_usage, fan_speed, f"{mhs_av:.2f}"))

    def update_gpu_hashrate(self, hashrate):
        """Update the GPU hashrate label."""
        self.gpu_hashrate_label.config(text=f"GPU Hashrate: {hashrate}")

    def clear_gpu_stats(self):
        """Clear the GPU statistics table."""
        for item in self.stats_tree.get_children():
            self.stats_tree.delete(item)

    def stop_mining(self):
        """Stop both GPU and CPU mining processes."""
        self.stop_cpu_mining()
        self.stop_gpu_mining()
        self.update_toggle_button_state()  # Ensure the button state is updated after stopping all miners

    def stop_cpu_mining(self):
        """Stop the CPU mining process."""
        if "monero" in self.mining_processes:
            self._stop_mining_process("monero")
            logging.info("Controller: CPU mining stopped")

    def stop_gpu_mining(self):
        """Stop the GPU mining processes."""
        if "gminer" in self.mining_processes:
            self._stop_mining_process("gminer")
            logging.info("Controller: Gminer mining stopped")
        if "teamredminer" in self.mining_processes:
            self._stop_mining_process("teamredminer")
            logging.info("Controller: TeamRedMiner mining stopped")

    def _stop_mining_process(self, process_key):
        """Stop a specific mining process and its children."""
        proc = self.mining_processes.get(process_key)
        if proc and proc.poll() is None:
            logging.info(f"Controller: Forcefully killing {process_key} mining process and its children...")
            try:
                # Use psutil to kill the process and all its children
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
                parent.wait()  # Ensure the process is fully terminated
                logging.info(f"Controller: {process_key.capitalize()} mining process forcefully terminated.")
            except Exception as e:
                logging.error(f"Controller: Error forcefully terminating {process_key} process: {e}")

        self.mining_processes.pop(process_key, None)

        # Reset the statistics for the stopped process
        if process_key == "monero":
            self.update_cpu_hashrate("N/A")
        elif process_key in ["gminer", "teamredminer"]:
            self.update_gpu_hashrate("N/A")
            self.clear_gpu_stats()

        self.update_toggle_button_state()  # Ensure the button state is updated after stopping the process

    def is_mining_active(self):
        """Check if any mining process is active."""
        return any(
            proc_key in self.mining_processes and self.mining_processes[proc_key].poll() is None
            for proc_key in ["monero", "gminer", "teamredminer"]
        )

    def update_toggle_button_state(self):
        """Update the toggle button state based on mining activity."""
        if self.is_mining_active():
            self.toggle_btn.config(text="Stop Mining", bootstyle="danger")
        else:
            if self.auto_control.get() == 1:
                if self.last_fetched_price is not None and (
                    self.last_fetched_price >= self.config["CPU_PRICE_THRESHOLD"] and self.last_fetched_price >= self.config["GPU_PRICE_THRESHOLD"]
                ):
                    self.toggle_btn.config(text="Price too high", bootstyle="warning")
                elif self.config.get("ENABLE_IDLE_MINING", False) and self.get_idle_time() < int(self.config["IDLE_TIME_THRESHOLD"]):
                    self.toggle_btn.config(text="Waiting on idle", bootstyle="warning")
            else:
                self.toggle_btn.config(text="Manual Start", bootstyle="primary")

    def on_closing(self):
        """Handle the window close event."""
        try:
            self.stop_mining()
        finally:
            self.root.destroy()

def main():
    root = ttk.Window(themename="darkly")
    iconPath = resource_path('logo.ico')
    root.iconbitmap(iconPath)
    app = MiningControlApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
