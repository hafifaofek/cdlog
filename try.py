import os
import time
import yaml
import threading
import socket
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import ssl

# Function to encrypt logs using Fernet symmetric encryption
def encrypt_logs(logs, key):
    f = Fernet(key)
    encrypted_logs = []
    for log in logs:
        encrypted_logs.append(f.encrypt(log.encode()))
    return encrypted_logs

# Function to print logs
def print_logs(logs):
    for log in logs:
        print(log)

# Connection manager class for both TCP and UDP
class ConnectionManager:
    def __init__(self, destination_ip, destination_port, protocol):
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.socket = None
        self.last_data_sent_time = None
        self.timeout_thread = None  # Thread for checking connection timeout
        self.connect()

    def connect(self):
        try:
            if self.protocol == "TCP":
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                self.socket = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.destination_ip)
                self.socket.connect((self.destination_ip, self.destination_port))
            elif self.protocol == "UDP":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print(f"{self.protocol} connection established.")
            self.last_data_sent_time = time.time()  # Initialize last_data_sent_time
            self.start_timeout_thread()  # Start the timeout thread
        except Exception as e:
            print("Error:", e)

    def send_logs(self, logs):
        try:
            for log in logs:
                if self.protocol == "TCP":
                    self.socket.sendall(log)
                elif self.protocol == "UDP":
                    self.socket.sendto(log, (self.destination_ip, self.destination_port))
            self.last_data_sent_time = time.time()  # Update last_data_sent_time
            print(f"Logs sent successfully over {self.protocol}!")
        except Exception as e:
            print("Error:", e)
            self.close_connection()

    def start_timeout_thread(self):
        # Thread for checking connection timeout
        self.timeout_thread = threading.Thread(target=self.check_timeout_thread)
        self.timeout_thread.start()

    def check_timeout_thread(self):
        while True:
            if self.socket and self.last_data_sent_time and (time.time() - self.last_data_sent_time) >= 300:
                print(f"Closing {self.protocol} connection due to timeout.")
                self.close_connection()
            time.sleep(60)  # Check timeout every minute

    def close_connection(self):
        if self.socket:
            self.socket.close()
            self.socket = None
        if self.timeout_thread:
            self.timeout_thread.join()  # Wait for the timeout thread to terminate
        self.timeout_thread = None

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file, connection_manager, encryption_key):
        super(LogFileHandler, self).__init__()
        self.log_file = log_file
        self.connection_manager = connection_manager
        self.encryption_key = encryption_key
        self.log_position = 0
        self.file_handle = None
        self.observer = None

    def start_file_tracking(self):
        # Open the log file for reading
        try:
            self.file_handle = open(self.log_file, 'r', encoding='utf-8', errors='ignore')
            # Get the initial position
            self.log_position = self.file_handle.tell()
        except:
            print(f"can't open file {self.log_file}")

    def stop_file_tracking(self):
        # Close the file handle
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
        # Stop observing the current log file
        if self.observer:
            self.observer.stop()
        self.observer = None

    def on_modified(self, event):
        if not event.is_directory and event.src_path == self.log_file:
            if self.file_handle is None:
                self.start_file_tracking()
            new_logs = self.collect_new_logs()
            if new_logs:
                print_logs(new_logs)
                # Encrypt new logs
                encrypted_logs = encrypt_logs(new_logs, self.encryption_key)
                # Send encrypted logs
                self.connection_manager.send_logs(encrypted_logs)

            # Check if the file has been rotated (size decreased)
            if os.path.exists(self.log_file) and os.path.getsize(self.log_file) < self.log_position:
                print("Log file has been rotated.")
                helper = self.log_file
                self.stop_file_tracking()
                # Update the log file path
                self.log_file = helper
                # Start tracking the new log file
                self.start_file_tracking()
                # Close the current connection
                self.connection_manager.close_connection()
                # Reconnect and start a new timeout thread
                self.connection_manager.connect()

    def collect_new_logs(self):
        new_logs = []
        self.file_handle.seek(self.log_position)
        for line in self.file_handle:
            new_logs.append(line.strip())
        self.log_position = self.file_handle.tell()
        return new_logs

    def send_initial_logs(self):
        if self.file_handle is None:
            self.start_file_tracking()
        self.file_handle.seek(0)
        initial_logs = []
        for line in self.file_handle:
            initial_logs.append(line.strip())
        self.log_position = self.file_handle.tell()
        for log in initial_logs:
            print(log)

    def create_observer(self):
        directory = os.path.dirname(self.log_file)
        if os.path.exists(directory):
            self.observer = Observer()
            self.observer.schedule(self, directory)
            self.observer.start()
        else:
            print(f"Directory {directory} does not exist.")

def main():
    with open("cdlog.conf", 'r') as f:
        config = yaml.safe_load(f)

    # Extract configuration parameters
    log_directories = config["log_directories"]
    destination_ip = config["destination_ip"]
    destination_port = config["destination_port"]
    encryption_key = config["encryption_key"]
    transport_protocol = config["transport_protocol"]

    # Create connection manager
    connection_manager = ConnectionManager(destination_ip, destination_port, transport_protocol)

    # Create handlers for each log file
    handlers = []  # Store handlers for sending initial logs later
    for log_dir in log_directories:
        directory = log_dir["directory"]
        formats = log_dir.get("formats", ["*"])  # Get formats if defined, otherwise use "*"

        # Assuming directory is the path to the directory or file
        if os.path.isdir(directory):
            # Handle as directory
            for root, _, files in os.walk(directory):
                for file in files:
                    for format in formats:
                        if file.endswith(format) or format == "*":
                            log_file = os.path.join(root, file)
                            # Create a new observer for each log file
                            event_handler = LogFileHandler(log_file, connection_manager, encryption_key)
                            event_handler.create_observer()
                            event_handler.send_initial_logs()
                            handlers.append(event_handler)
        else:
            # Handle as file
            for format in formats:
                if directory.endswith(format) or format == "*":
                    log_file = directory
                    # Create a new observer for each log file
                    event_handler = LogFileHandler(log_file, connection_manager, encryption_key)
                    event_handler.create_observer()
                    event_handler.send_initial_logs()
                    handlers.append(event_handler)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Stop and join observers
        for handler in handlers:
            handler.stop_file_tracking()

if __name__ == "__main__":
    main()
