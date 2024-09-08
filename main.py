import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, Toplevel, filedialog
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
    "TBM_EXECUTABLE_PATH": r".\TBMiner.exe"
}

# Load or initialize configuration
def load_config():
    """Load configuration from the config file, or use defaults if the file doesn't exist."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    else:
        return DEFAULT_CONFIG

config = load_config()

# Assign global variables
# General settings
CPU_PRICE_THRESHOLD = float(config["CPU_PRICE_THRESHOLD"])
GPU_PRICE_THRESHOLD = float(config["GPU_PRICE_THRESHOLD"])
AMBER_API_SITE_ID = config["AMBER_API_SITE_ID"]
AMBER_API_KEY = config["AMBER_API_KEY"]
WORKER_NAME = config["WORKER_NAME"]

# CPU Mining settings
CPU_POOL_URL = config["CPU_POOL_URL"]
CPU_POOL_PORT = int(config["CPU_POOL_PORT"])
CPU_WALLET = config["CPU_WALLET"]
XMRIG_EXECUTABLE_PATH = config["XMRIG_EXECUTABLE_PATH"]

# GPU Mining settings
GPU_POOL_URL = config["GPU_POOL_URL"]
GPU_POOL_PORT = int(config["GPU_POOL_PORT"])
GPU_WALLET = config["GPU_WALLET"]
TBM_EXECUTABLE_PATH = config["TBM_EXECUTABLE_PATH"]

# Static variables
VERSION = "0.1.10"
LOG_FILE = "amber-kawpow-miner.log"
TBM_MINING_API_URL = "http://127.0.0.1:4068/summary"
EXECUTABLE_NAME = "amber-kawpow-miner.exe"
GITHUB_REPO = "aplace-lab/amber-kawpow-miner"

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Variable to store the last fetched electricity price
last_fetched_price = None

def save_config():
    """Save the current configuration to a file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    logging.info("Controller: Preferences saved")

def get_api_url():
    """Construct the Amber API URL based on the site ID and API key."""
    if AMBER_API_SITE_ID and AMBER_API_KEY:
        return f"https://api.amber.com.au/v1/sites/{AMBER_API_SITE_ID}/prices/current?next=0&previous=0"
    return None

def check_for_updates():
    """Check if the current version is the latest release on GitHub."""
    try:
        response = requests.get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest")
        latest_release = response.json()["tag_name"]
        asset = next(asset for asset in response.json()["assets"] if asset["name"] == EXECUTABLE_NAME)

        if latest_release > VERSION:
            download_url = asset["browser_download_url"]
            prompt_update(latest_release, download_url)
        else:
            logging.info("Controller: Application already at latest version")

    except Exception as e:
        logging.error(f"Controller: Error checking for updates: {e}")

def prompt_update(latest_release, download_url):
    """Prompt the user to update to the latest version and download the new executable."""
    message = f"A new version ({latest_release}) is available. Would you like to download now?"
    response = messagebox.askokcancel("Update Available", message)
    
    if response:
        webbrowser.open(download_url)

def get_idle_time():
    """Get the system idle time in seconds."""
    return (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000

class MiningControlApp:
    def __init__(self, root):
        logging.info("Controller: Application starting")
        self.root = root
        self.root.title("Amber Kawpow & Monero Miner")
        self.root.geometry("650x500")
        self.root.resizable(False, False)

        self.mining_processes = {}  # To keep track of subprocesses

        self.create_menu()          # Create the menu bar
        self.create_main_frame()
        self.create_summary_section()
        self.create_control_section()
        self.create_stats_section()

        self.reload_config()        # Reload config to ensure all attributes are set
        check_for_updates()         # Check for updates
        self.monitor_conditions()   # Start monitoring idle time and price thresholds
        self.update_price()         # Start fetching the electricity price every 5 minutes
        logging.info("Controller: Application finished loading")

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close event

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
        file_menu_button.pack(side=LEFT)

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

        self.stats_tree = ttk.Treeview(stats_frame, columns=("gpu", "temp", "power", "fan", "hashrate"), show='headings', height=5)
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

        self.price_label = ttk.Label(information_frame, text=f"Version: {VERSION}", font="-size 10")
        self.price_label.pack(anchor=W)

    def open_settings(self):
        """Open the settings window."""
        settings_window = Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x560")
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
        self.add_setting_field(general_frame, "Amber Site ID:", config["AMBER_API_SITE_ID"], "amber_site_id_entry")
        self.add_setting_field(general_frame, "Amber API Key:", config["AMBER_API_KEY"], "amber_api_key_entry")
        self.add_setting_field(general_frame, "Worker Name:", config["WORKER_NAME"], "worker_name_entry")
        self.add_setting_field(general_frame, "CPU Electricity Cost Threshold ($/kWh):", config["CPU_PRICE_THRESHOLD"], "cpu_price_threshold_entry")
        self.add_setting_field(general_frame, "GPU Electricity Cost Threshold ($/kWh):", config["GPU_PRICE_THRESHOLD"], "gpu_price_threshold_entry")
        self.add_setting_field(general_frame, "Idle Time Threshold (seconds):", config["IDLE_TIME_THRESHOLD"], "idle_time_threshold_entry")

        self.enable_idle_mining_var = ttk.IntVar(value=config.get("ENABLE_IDLE_MINING", 0))
        self.enable_idle_mining = ttk.Checkbutton(
            general_frame, 
            text="Enable Idle Mining",
            variable=self.enable_idle_mining_var,
            bootstyle="round-toggle"
        )
        self.enable_idle_mining.pack(anchor=W, pady=(10, 0))

        # CPU Mining settings
        self.add_setting_field(cpu_frame, "Pool URL:", config.get("CPU_POOL_URL", config["CPU_POOL_URL"]), "cpu_pool_url_entry")
        self.add_setting_field(cpu_frame, "Pool Port:", str(config.get("CPU_POOL_PORT", config["CPU_POOL_PORT"])), "cpu_pool_port_entry")
        self.add_setting_field(cpu_frame, "Wallet:", config.get("CPU_WALLET", ""), "cpu_wallet_entry")
        self.add_setting_field(cpu_frame, "XMRig Executable Path:", config["XMRIG_EXECUTABLE_PATH"], "xmrig_path_entry")
        self.create_browse_xmr_button(cpu_frame)

        # GPU Mining settings
        self.add_setting_field(gpu_frame, "Pool URL:", config.get("GPU_POOL_URL", config["GPU_POOL_URL"]), "gpu_pool_url_entry")
        self.add_setting_field(gpu_frame, "Pool Port:", str(config.get("GPU_POOL_PORT", config["GPU_POOL_PORT"])), "gpu_pool_port_entry")
        self.add_setting_field(gpu_frame, "Wallet:", config.get("GPU_WALLET", ""), "gpu_wallet_entry")
        self.add_setting_field(gpu_frame, "TeamBlackMiner Executable Path:", config["TBM_EXECUTABLE_PATH"], "tbminer_path_entry")
        self.create_browse_tbm_button(gpu_frame)

        # Save button
        self.create_save_button(settings_window)

    def add_setting_field(self, window, label_text, default_value, entry_var_name):
        """Helper method to add a labeled input field to the settings window."""
        ttk.Label(window, text=label_text).pack(anchor=W, padx=10, pady=5)
        entry = ttk.Entry(window)
        entry.insert(0, default_value)
        entry.pack(fill=X, padx=10, pady=5)
        setattr(self, entry_var_name, entry)

    def create_browse_tbm_button(self, window):
        """Create a button for browsing the TBMiner executable."""
        browse_button = ttk.Button(window, text="Browse...", command=self.browse_tbminer_path)
        browse_button.pack(anchor=E, padx=10, pady=5)

    def create_browse_xmr_button(self, window):
        """Create a button for browsing the XMRig executable."""
        browse_button = ttk.Button(window, text="Browse...", command=self.browse_xmrig_path)
        browse_button.pack(anchor=E, padx=10, pady=5)

    def create_save_button(self, window):
        """Create a button for saving settings."""
        save_button = ttk.Button(window, text="Save", command=lambda: self.save_settings(window))
        save_button.pack(anchor=E, padx=10, pady=20)

    def browse_tbminer_path(self):
        """Open a file dialog to browse for the TBMiner executable."""
        file_path = filedialog.askopenfilename(title="Select TBMiner Executable", filetypes=[("Executable Files", "*.exe")])
        if file_path:
            self.tbminer_path_entry.delete(0, END)
            self.tbminer_path_entry.insert(0, file_path)

    def browse_xmrig_path(self):
        """Open a file dialog to browse for the TBMiner executable."""
        file_path = filedialog.askopenfilename(title="Select XMRig Executable", filetypes=[("Executable Files", "*.exe")])
        if file_path:
            self.xmrig_path_entry.delete(0, END)
            self.xmrig_path_entry.insert(0, file_path)

    def save_settings(self, settings_window):
        """Save the settings from the input fields."""
        global CPU_PRICE_THRESHOLD, GPU_PRICE_THRESHOLD, AMBER_API_SITE_ID, AMBER_API_KEY, POOL_HOSTNAME, POOL_PORT, POOL_WALLET, WORKER_NAME, TBM_EXECUTABLE_PATH, XMRIG_EXECUTABLE_PATH

        # Update the config dictionary with the new settings
        config["CPU_PRICE_THRESHOLD"] = float(self.cpu_price_threshold_entry.get())
        config["GPU_PRICE_THRESHOLD"] = float(self.gpu_price_threshold_entry.get())
        config["AMBER_API_SITE_ID"] = self.amber_site_id_entry.get()
        config["AMBER_API_KEY"] = self.amber_api_key_entry.get()
        config["WORKER_NAME"] = self.worker_name_entry.get()
        config["ENABLE_IDLE_MINING"] = self.enable_idle_mining_var.get()
        config["IDLE_TIME_THRESHOLD"] = int(self.idle_time_threshold_entry.get())

        # CPU Mining settings
        config["CPU_POOL_URL"] = self.cpu_pool_url_entry.get()
        config["CPU_POOL_PORT"] = int(self.cpu_pool_port_entry.get())
        config["CPU_WALLET"] = self.cpu_wallet_entry.get()
        config["XMRIG_EXECUTABLE_PATH"] = self.xmrig_path_entry.get()

        # GPU Mining settings
        config["GPU_POOL_URL"] = self.gpu_pool_url_entry.get()
        config["GPU_POOL_PORT"] = int(self.gpu_pool_port_entry.get())
        config["GPU_WALLET"] = self.gpu_wallet_entry.get()
        config["TBM_EXECUTABLE_PATH"] = self.tbminer_path_entry.get()

        # Save the updated configuration
        save_config()

        # Reload the configuration to apply changes immediately
        settings_window.destroy()
        self.reload_config()  # Reload the config after the settings window is destroyed

    def create_browse_xmr_button(self, window):
        """Create a button for browsing the XMRig executable."""
        browse_button = ttk.Button(window, text="Browse...", command=self.browse_xmrig_path)
        browse_button.pack(anchor=E, padx=10, pady=5)

    def create_browse_tbm_button(self, window):
        """Create a button for browsing the TBMiner executable."""
        browse_button = ttk.Button(window, text="Browse...", command=self.browse_tbminer_path)
        browse_button.pack(anchor=E, padx=10, pady=5)

    def reload_config(self):
        """Reload configuration from the file and update global variables."""
        global config, CPU_PRICE_THRESHOLD, GPU_PRICE_THRESHOLD, AMBER_API_SITE_ID, AMBER_API_KEY, WORKER_NAME, TBM_EXECUTABLE_PATH, XMRIG_EXECUTABLE_PATH

        config = load_config()

        logging.info("Controller: Config reloading")

        # General settings
        CPU_PRICE_THRESHOLD = float(config["CPU_PRICE_THRESHOLD"])
        GPU_PRICE_THRESHOLD = float(config["GPU_PRICE_THRESHOLD"])
        AMBER_API_SITE_ID = config["AMBER_API_SITE_ID"]
        AMBER_API_KEY = config["AMBER_API_KEY"]
        WORKER_NAME = config["WORKER_NAME"]

        # CPU Mining settings
        self.cpu_pool_url = config["CPU_POOL_URL"]
        self.cpu_pool_port = int(config["CPU_POOL_PORT"])
        self.cpu_wallet = config["CPU_WALLET"]
        XMRIG_EXECUTABLE_PATH = config["XMRIG_EXECUTABLE_PATH"]

        # GPU Mining settings
        self.gpu_pool_url = config["GPU_POOL_URL"]
        self.gpu_pool_port = int(config["GPU_POOL_PORT"])
        self.gpu_wallet = config["GPU_WALLET"]
        TBM_EXECUTABLE_PATH = config["TBM_EXECUTABLE_PATH"]

        # Validate miner executables on startup
        self.validate_miner_executables()

    def monitor_conditions(self):
        """Monitor idle time and price conditions to control mining."""
        if config.get("ENABLE_IDLE_MINING", False):
            idle_time = get_idle_time()
            idle_threshold = int(config["IDLE_TIME_THRESHOLD"])

            if idle_time >= idle_threshold:
                self.control_mining_based_on_price()
            else:
                self.stop_mining()
        else:
            self.control_mining_based_on_price()

        self.root.after(1000, self.monitor_conditions)

    def fetch_electricity_price(self):
        """Fetch the current electricity price from the Amber API."""
        global last_fetched_price
        api_url = get_api_url()
        if api_url:
            headers = {
                'Authorization': f'Bearer {AMBER_API_KEY}',
            }
            try:
                response = requests.get(api_url, headers=headers)
                data = response.json()
                for entry in data:
                    if entry['channelType'] == 'general':
                        last_fetched_price = entry['perKwh'] / 100  # Convert from c/kWh to $/kWh
                        return last_fetched_price
            except Exception as e:
                logging.error(f"Controller: Error accessing current price: {e}")
                return None
        else:
            messagebox.showerror("Configuration Error", "Amber API Site ID or API Key is missing.")
            self.open_settings()
            return None

    def control_mining_based_on_price(self):
        """Control mining based on the last fetched electricity price."""
        global last_fetched_price
        if last_fetched_price is not None:
            self.price_label.config(text=f"General Usage: ${last_fetched_price:.2f}/kWh")

            if self.auto_control.get() == 1:
                cpu_mining_active = "monero" in self.mining_processes
                gpu_mining_active = "kawpow" in self.mining_processes

                # Handle CPU mining based on price threshold
                if last_fetched_price < CPU_PRICE_THRESHOLD and not cpu_mining_active:
                    logging.info(f"Controller: Electricity cost below threshold ({last_fetched_price} < {CPU_PRICE_THRESHOLD})")
                    self.start_cpu_mining()
                elif last_fetched_price >= CPU_PRICE_THRESHOLD and cpu_mining_active:
                    logging.info(f"Controller: Electricity cost above threshold ({last_fetched_price} > {CPU_PRICE_THRESHOLD})")
                    self.stop_cpu_mining()

                # Handle GPU mining based on price threshold
                if last_fetched_price < GPU_PRICE_THRESHOLD and not gpu_mining_active:
                    logging.info(f"Controller: Electricity cost below threshold ({last_fetched_price} < {CPU_PRICE_THRESHOLD})")
                    self.start_gpu_mining()
                elif last_fetched_price >= GPU_PRICE_THRESHOLD and gpu_mining_active:
                    logging.info(f"Controller: Electricity cost above threshold ({last_fetched_price} > {CPU_PRICE_THRESHOLD})")
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
            # Validate TBMiner
            result = subprocess.run(
                [TBM_EXECUTABLE_PATH, '--version'],
                capture_output=True,
                text=True,
                check=True
            )
            if "Miner version" in result.stdout:
                logging.info("Controller: TBMiner executable validated successfully.")
            else:
                raise ValueError("Invalid TBMiner executable output.")

            # Validate XMRig
            result = subprocess.run(
                [XMRIG_EXECUTABLE_PATH, '--version'],
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
            start_cmd = (
                f"{XMRIG_EXECUTABLE_PATH} --url={self.cpu_pool_url}:{self.cpu_pool_port} --tls --user={self.cpu_wallet} "
                f"--pass=x --coin=monero --print-time=2"
            )
            proc = subprocess.Popen(start_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, text=True)
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
        """Start the GPU (Kawpow) mining process."""
        if "kawpow" not in self.mining_processes:
            self.mining_processes["kawpow"] = threading.Thread(target=self.run_kawpow_mining)
            self.mining_processes["kawpow"].start()
            logging.info("Controller: GPU mining started")

    def run_kawpow_mining(self):
        """Run the Kawpow (GPU) mining process."""
        try:
            start_cmd = (
                f"{TBM_EXECUTABLE_PATH} --algo kawpow --hostname {self.gpu_pool_url} --port {self.gpu_pool_port} "
                f"--wallet {self.gpu_wallet} --worker-name {WORKER_NAME} --api"
            )
            proc = subprocess.Popen(start_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, text=True)
            self.mining_processes["kawpow"] = proc  # Track the process
            
            # Log the output
            threading.Thread(target=self.monitor_kawpow_output, args=(proc,), daemon=True).start()
            self.update_miner_stats()  # Start stats updating
            proc.wait()  # Wait for the process to complete
        except Exception as e:
            logging.error(f"Controller: Error in Kawpow mining process: {e}")
        finally:
            self.mining_processes.pop("kawpow", None)
            self.update_gpu_hashrate("N/A")
            self.clear_gpu_stats()
            self.update_toggle_button_state()  # Ensure the button state is updated after the miner stops

    def monitor_kawpow_output(self, proc):
        """Monitor TBMiner (Kawpow) output and log it to file."""
        try:
            for line in iter(proc.stdout.readline, ''):
                if line:
                    logging.info(f"TBMiner: {line.strip()}")
            proc.stdout.close()
        except Exception as e:
            logging.error(f"Controller: Error in Kawpow mining process: {e}")
        finally:
            if proc.poll() is None:
                proc.wait()
            self.mining_processes.pop("kawpow", None)
            self.update_gpu_hashrate("N/A")
            self.clear_gpu_stats()
            self.update_toggle_button_state()  # Ensure the button state is updated after the miner stops

    def update_miner_stats(self):
        """Fetch and update miner statistics."""
        if "kawpow" in self.mining_processes:  # Only update GPU stats if mining is active
            try:
                summary_response = requests.get(TBM_MINING_API_URL, timeout=5).json()

                miner_stats = summary_response.get("miner", {})
                total_hashrate = miner_stats.get("total_hashrate", 0)
                hashrate = f"{total_hashrate / 1e6:.2f} MH/s"

                self.update_gpu_hashrate(hashrate)

                self.clear_gpu_stats()
                self.populate_gpu_stats(summary_response.get("devices", {}))

            except requests.exceptions.RequestException as e:
                logging.error(f"Controller: Error fetching miner stats: {e}")

            # Repeat every 2 seconds while mining
            self.root.after(2000, self.update_miner_stats)

    def update_cpu_hashrate(self, hashrate):
        """Update the CPU hashrate label."""
        self.cpu_hashrate_label.config(text=f"CPU Hashrate: {hashrate}")

    def populate_gpu_stats(self, devices):
        """Populate the GPU statistics table."""
        for gpu_id, gpu_stats in devices.items():
            gpu_name = gpu_stats.get("board_name", f"GPU {gpu_id}")
            gpu_temp = gpu_stats.get("gpu_temp", "N/A")
            power_usage = gpu_stats.get("watt", "N/A")
            fan_speed = gpu_stats.get("fan", "N/A")
            gpu_hashrate = gpu_stats.get("hashrate", 0) / 1e6  # Convert to MH/s

            self.stats_tree.insert("", "end", values=(gpu_name, gpu_temp, power_usage, fan_speed, f"{gpu_hashrate:.2f}"))

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
        """Stop the GPU mining process."""
        if "kawpow" in self.mining_processes:
            self._stop_mining_process("kawpow")
            logging.info("Controller: GPU mining stopped")

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
        elif process_key == "kawpow":
            self.update_gpu_hashrate("N/A")
            self.clear_gpu_stats()

        self.update_toggle_button_state()  # Ensure the button state is updated after stopping the process

    def is_mining_active(self):
        """Check if any mining process is active."""
        return (
            "monero" in self.mining_processes and self.mining_processes["monero"].poll() is None or
            "kawpow" in self.mining_processes
        )

    def update_toggle_button_state(self):
        """Update the toggle button state based on mining activity."""
        if self.is_mining_active():
            self.toggle_btn.config(text="Stop Mining", bootstyle="danger")
        else:
            if self.auto_control.get() == 1:
                if last_fetched_price is not None and (
                    last_fetched_price >= CPU_PRICE_THRESHOLD and last_fetched_price >= GPU_PRICE_THRESHOLD
                ):
                    self.toggle_btn.config(text="Price too high", bootstyle="warning")
                elif config.get("ENABLE_IDLE_MINING", False) and get_idle_time() < int(config["IDLE_TIME_THRESHOLD"]):
                    self.toggle_btn.config(text="Waiting on idle", bootstyle="warning")
            else:
                self.toggle_btn.config(text="Manual Start", bootstyle="primary")

    def on_closing(self):
        """Handle the window close event."""
        try:
            self.stop_mining()
        finally:
            self.root.destroy()

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def main():
    root = ttk.Window(themename="darkly")
    iconPath = resource_path('logo.ico')
    root.iconbitmap(iconPath)
    app = MiningControlApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
