import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, Toplevel, filedialog
import requests
import subprocess
import threading
import psutil
import socket
import json
import os

# Configuration file
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "PRICE_THRESHOLD": 0.30,
    "AMBER_API_SITE_ID": "",
    "AMBER_API_KEY": "",
    "POOL_HOSTNAME": "rvn.2miners.com",
    "POOL_PORT": 6060,
    "POOL_WALLET": "",
    "WORKER_NAME": socket.gethostname(),
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
PRICE_THRESHOLD = config["PRICE_THRESHOLD"]
AMBER_API_SITE_ID = config["AMBER_API_SITE_ID"]
AMBER_API_KEY = config["AMBER_API_KEY"]
POOL_HOSTNAME = config["POOL_HOSTNAME"]
POOL_PORT = config["POOL_PORT"]
POOL_WALLET = config["POOL_WALLET"]
WORKER_NAME = config["WORKER_NAME"]
TBM_EXECUTABLE_PATH = config["TBM_EXECUTABLE_PATH"]

# Static variables
VERSION = "0.0.7"
MINING_API_URL = "http://127.0.0.1:4068/summary"
STOP_MINING_CMD = "taskkill /F /IM TBMiner.exe"

def save_config():
    """Save the current configuration to a file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def get_api_url():
    """Construct the Amber API URL based on the site ID and API key."""
    if AMBER_API_SITE_ID and AMBER_API_KEY:
        return f"https://api.amber.com.au/v1/sites/{AMBER_API_SITE_ID}/prices/current?next=0&previous=0"
    return None

class MiningControlApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Amber Kawpow Miner")
        self.root.geometry("650x500")
        self.root.resizable(False, False)

        self.mining_process = None  # To keep track of the subprocess

        self.create_menu()  # Create the menu bar
        self.create_main_frame()
        self.create_summary_section()
        self.create_control_section()
        self.create_stats_section()

        # Validate miner executable on startup
        self.validate_miner_executable()

        # Start the price update loop
        self.update_price()

        # Handle window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_menu(self):
        """Create a custom menu bar using a Frame."""
        menu_frame = ttk.Frame(self.root, padding=(5, 2))
        menu_frame.pack(fill=X, side=TOP)

        file_menu_button = ttk.Menubutton(menu_frame, text="File", bootstyle="dark", direction=RIGHT)
        file_menu = ttk.Menu(file_menu_button, tearoff=0)
        file_menu.add_command(label="Preferences", command=self.open_settings)
        file_menu.add_command(label="About", command=self.open_about)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        file_menu_button.config(menu=file_menu)
        file_menu_button.pack(side=LEFT)

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

        self.hashrate_label = ttk.Label(summary_frame, text="Current Hashrate: N/A", font="-size 12")
        self.hashrate_label.pack(anchor=W)

        self.uptime_label = ttk.Label(summary_frame, text="Uptime: N/A", font="-size 12")
        self.uptime_label.pack(anchor=W)

    def create_control_section(self):
        """Create the mining control section."""
        control_frame = ttk.Labelframe(self.main_frame, text="Mining Control", padding=(10, 10))
        control_frame.pack(fill=X, pady=(0, 10))

        self.toggle_btn = ttk.Button(control_frame, text="Start Mining", command=self.toggle_mining, bootstyle="primary", width=15)
        self.toggle_btn.pack(pady=(0, 5))

        self.auto_control = ttk.IntVar()
        self.auto_control_check = ttk.Checkbutton(control_frame, text="Auto Control Mining", variable=self.auto_control, bootstyle="round-toggle")
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
        settings_window.geometry("400x650")
        settings_window.resizable(False, False)

        self.create_settings_fields(settings_window)
        self.create_browse_button(settings_window)
        self.create_save_button(settings_window)

    def create_settings_fields(self, window):
        """Create input fields for settings."""
        self.add_setting_field(window, "Electricity Price Threshold ($/kWh):", str(config["PRICE_THRESHOLD"]), "price_threshold_entry")
        self.add_setting_field(window, "Amber API Site ID:", config["AMBER_API_SITE_ID"], "amber_site_id_entry")
        self.add_setting_field(window, "Amber API Key:", config["AMBER_API_KEY"], "amber_api_key_entry")
        self.add_setting_field(window, "Pool Hostname:", config["POOL_HOSTNAME"], "pool_hostname_entry")
        self.add_setting_field(window, "Pool Port:", str(config["POOL_PORT"]), "pool_port_entry")
        self.add_setting_field(window, "Pool Wallet:", config["POOL_WALLET"], "pool_wallet_entry")
        self.add_setting_field(window, "Pool Worker Name:", config["WORKER_NAME"], "worker_name_entry")
        self.add_setting_field(window, "TeamBlackMiner Executable Path:", config["TBM_EXECUTABLE_PATH"], "tbminer_path_entry")

    def add_setting_field(self, window, label_text, default_value, entry_var_name):
        """Helper method to add a labeled input field to the settings window."""
        ttk.Label(window, text=label_text).pack(anchor=W, padx=10, pady=5)
        entry = ttk.Entry(window)
        entry.insert(0, default_value)
        entry.pack(fill=X, padx=10, pady=5)
        setattr(self, entry_var_name, entry)

    def create_browse_button(self, window):
        """Create a button for browsing the TBMiner executable."""
        browse_button = ttk.Button(window, text="Browse...", command=self.browse_tbminer_path)
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

    def save_settings(self, settings_window):
        """Save the settings from the input fields."""
        global PRICE_THRESHOLD, AMBER_API_SITE_ID, AMBER_API_KEY, POOL_HOSTNAME, POOL_PORT, POOL_WALLET, WORKER_NAME, TBM_EXECUTABLE_PATH

        config["PRICE_THRESHOLD"] = float(self.price_threshold_entry.get())
        config["AMBER_API_SITE_ID"] = self.amber_site_id_entry.get()
        config["AMBER_API_KEY"] = self.amber_api_key_entry.get()
        config["POOL_HOSTNAME"] = self.pool_hostname_entry.get()
        config["POOL_PORT"] = int(self.pool_port_entry.get())
        config["POOL_WALLET"] = self.pool_wallet_entry.get()
        config["WORKER_NAME"] = self.worker_name_entry.get()
        config["TBM_EXECUTABLE_PATH"] = self.tbminer_path_entry.get()

        # Save the updated configuration
        save_config()

        # Reload the configuration to apply changes immediately
        self.reload_config()

        # Close the settings window after saving
        settings_window.destroy()

    def reload_config(self):
        """Reload configuration from the file and update global variables."""
        global config, PRICE_THRESHOLD, AMBER_API_SITE_ID, AMBER_API_KEY, POOL_HOSTNAME, POOL_PORT, POOL_WALLET, WORKER_NAME, TBM_EXECUTABLE_PATH

        config = load_config()

        PRICE_THRESHOLD = config["PRICE_THRESHOLD"]
        AMBER_API_SITE_ID = config["AMBER_API_SITE_ID"]
        AMBER_API_KEY = config["AMBER_API_KEY"]
        POOL_HOSTNAME = config["POOL_HOSTNAME"]
        POOL_PORT = config["POOL_PORT"]
        POOL_WALLET = config["POOL_WALLET"]
        WORKER_NAME = config["WORKER_NAME"]
        TBM_EXECUTABLE_PATH = config["TBM_EXECUTABLE_PATH"]

        self.validate_miner_executable()
        self.update_price()
        

    def get_current_price(self):
        """Fetch the current electricity price from the Amber API."""
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
                        current_price = entry['perKwh'] / 100  # Convert from c/kWh to $/kWh
                        return current_price
            except Exception as e:
                print(f"Error accessing current price: {e}")
                return None
        else:
            messagebox.showerror("Configuration Error", "Amber API Site ID or API Key is missing.")
            return None

    def update_price(self):
        """Update the price label and control mining based on the current price."""
        current_price = self.get_current_price()
        if current_price is not None:
            self.price_label.config(text=f"General Usage: ${current_price:.2f}/kWh")
            if self.auto_control.get() == 1:
                if current_price < PRICE_THRESHOLD:
                    self.start_mining()
                else:
                    self.stop_mining()
        else:
            self.price_label.config(text="Error retrieving price")

        self.root.after(300000, self.update_price)  # Update every 5 minutes

    def validate_miner_executable(self):
        """Validate the miner executable path by checking the version."""
        try:
            # Run the command to check the miner version
            result = subprocess.run(
                [TBM_EXECUTABLE_PATH, '--version'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Validate the expected output
            if "Miner version" in result.stdout:
                print("Miner executable validated successfully.")
                return True
            else:
                raise ValueError("Invalid miner executable output.")
        
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError) as e:
            messagebox.showerror("Validation Error", f"Failed to validate miner executable: {e}")
            return False

    def toggle_mining(self):
        """Toggle mining on or off."""
        if self.is_mining_active():
            self.stop_mining()
        else:
            self.start_mining()

    def start_mining(self):
        """Start the mining process."""
        if not self.is_mining_active():
            self.mining_thread = threading.Thread(target=self.run_mining)
            self.mining_thread.start()
            self.toggle_btn.config(text="Stop Mining", bootstyle="danger")
            self.root.after(2000, self.update_miner_stats)  # Start after 2 second delay

    def run_mining(self):
        """Run the mining process."""
        try:
            start_cmd = (
                f"{TBM_EXECUTABLE_PATH} --algo kawpow --hostname {POOL_HOSTNAME} --port {POOL_PORT} "
                f"--wallet {POOL_WALLET} --worker-name {WORKER_NAME} --api"
            )
            self.mining_process = subprocess.Popen(start_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, text=True)
            self.mining_process.wait()  # Wait for the process to complete
        except Exception as e:
            print(f"Error in mining process: {e}")
        finally:
            self.mining_process = None
            self.toggle_btn.config(text="Start Mining", bootstyle="primary")
            self.update_hashrate("N/A")
            self.clear_gpu_stats()

    def update_miner_stats(self):
        """Fetch and update miner statistics."""
        if self.is_mining_active():
            try:
                print("Attempting to fetch miner stats...")
                summary_response = requests.get(MINING_API_URL, timeout=5).json()

                miner_stats = summary_response.get("miner", {})
                total_hashrate = miner_stats.get("total_hashrate", 0)
                uptime_minutes = miner_stats.get("uptime_minutes", 0)
                hashrate = f"{total_hashrate / 1e6:.2f} MH/s"
                uptime = f"{uptime_minutes} minutes"

                self.update_hashrate(hashrate)
                self.update_uptime(uptime)

                self.clear_gpu_stats()
                self.populate_gpu_stats(summary_response.get("devices", {}))

            except requests.exceptions.RequestException as e:
                print(f"Error fetching miner stats: {e}")

            self.root.after(2000, self.update_miner_stats)

    def populate_gpu_stats(self, devices):
        """Populate the GPU statistics table."""
        for gpu_id, gpu_stats in devices.items():
            gpu_name = gpu_stats.get("board_name", f"GPU {gpu_id}")
            gpu_temp = gpu_stats.get("gpu_temp", "N/A")
            power_usage = gpu_stats.get("watt", "N/A")
            fan_speed = gpu_stats.get("fan", "N/A")
            gpu_hashrate = gpu_stats.get("hashrate", 0) / 1e6  # Convert to MH/s

            self.stats_tree.insert("", "end", values=(gpu_name, gpu_temp, power_usage, fan_speed, f"{gpu_hashrate:.2f}"))

    def update_hashrate(self, hashrate):
        """Update the hashrate label."""
        self.hashrate_label.config(text=f"Hashrate: {hashrate}")

    def update_uptime(self, uptime):
        """Update the uptime label."""
        self.uptime_label.config(text=f"Uptime: {uptime}")

    def clear_gpu_stats(self):
        """Clear the GPU statistics table."""
        for item in self.stats_tree.get_children():
            self.stats_tree.delete(item)

    def stop_mining(self):
        """Stop the mining process."""
        if self.is_mining_active():
            stop_thread = threading.Thread(target=self._stop_mining_process)
            stop_thread.start()

    def _stop_mining_process(self):
        """Run the stop mining command."""
        subprocess.run(STOP_MINING_CMD, shell=True)
        if self.mining_thread.is_alive():
            self.mining_thread.join()
        self.mining_process = None
        self.toggle_btn.config(text="Start Mining", bootstyle="primary")
        self.update_hashrate("N/A")
        self.update_uptime("N/A")
        self.clear_gpu_stats()

    def is_mining_active(self):
        """Check if the mining process is active."""
        return self.mining_process is not None and psutil.pid_exists(self.mining_process.pid)

    def on_closing(self):
        """Handle the window close event."""
        try:
            self.stop_mining()
        finally:
            self.root.destroy()


def main():
    root = ttk.Window(themename="darkly")
    app = MiningControlApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
