import os
import time
import yaml
import threading
import socket
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import ssl
import logging

#logging.basicConfig(filename='/etc/cdlog/cdlog.log', level=logging.INFO)
# Configure logging to include timestamps
logging.basicConfig(
    filename='/etc/cdlog/cdlog.log', 
    level=logging.INFO,
    format='%(levelname)s - %(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
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
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                if SERVER_CERT_FILE:
                    ssl_context.load_verify_locations(cafile=SERVER_CERT_FILE)
                ssl_client_socket = ssl_context.wrap_socket(client_socket, server_hostname=self.destination_ip)
                self.socket = ssl_client_socket
                self.socket.connect((self.destination_ip, self.destination_port))
                logging.info("TCP connection established.")
            
            elif self.protocol == "UDP":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                logging.info("UDP connection established.")
            print(f"{self.protocol} connection established.")
            self.last_data_sent_time = time.time()  # Initialize last_data_sent_time
            self.start_timeout_thread()  # Start the timeout thread
        except Exception as e:
            logging.error(f"Error in connection establishment: {e}")
            print("Error:", e)

    def send_logs(self, logs, file_name):
        mone = 0
        try:
            if type(logs) is list:
                logs = logs[0]
            mone = mone + 1
            if self.protocol == "TCP":
                self.socket.sendall(logs)
                #logging.info(f"Sent log over TCP from file - {file_name}")
            elif self.protocol == "UDP":
                #self.socket.sendto(logs, (self.destination_ip, self.destination_port))
                self.socket.sendto(logs.encode(), (self.destination_ip, self.destination_port))
                #logging.info(f"Sent log over UDP from file - {file_name}.")
            self.last_data_sent_time = time.time()  # Update last_data_sent_time
            #logging.info(f"{mone} Logs sent successfully over {self.protocol} from file {file_name} to {self.destination_ip} on {self.destination_port}")
            #print(f"Logs sent successfully over {self.protocol}!")
        except Exception as e:
            logging.error(f"Error in sending logs: {e}")
            print("Error:", e)
            self.close_connection()

    def start_timeout_thread(self):
        # Thread for checking connection timeout
        self.timeout_thread = threading.Thread(target=self.check_timeout_thread)
        self.timeout_thread.start()

    def check_timeout_thread(self):
        while True:
            if self.socket and self.last_data_sent_time and (time.time() - self.last_data_sent_time) >= 300:
                logging.info(f"Closing {self.protocol} connection due to timeout.")
                print(f"Closing {self.protocol} connection due to timeout.")
                self.close_connection()
            time.sleep(60)  # Check timeout every minute

    def close_connection(self):
        if self.socket:
            self.socket.close()
            self.socket = None
        if self.timeout_thread:
            #self.timeout_thread.join()  # Wait for the timeout thread to terminate
            pass
        self.timeout_thread = None

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file, connection_manager, encryption_key, time_to_sent_logs_on_agent):
        super(LogFileHandler, self).__init__()
        self.log_file = log_file
        self.connection_manager = connection_manager
        self.encryption_key = encryption_key
        self.log_position = 0
        self.file_handle = None
        self.observer = None
        self.log_count = 0
        self.time_to_sent_logs_on_agent = time_to_sent_logs_on_agent
        self.log_logs_count_thread = threading.Thread(target=self.log_count_to_itself)
        self.log_logs_count_thread.start()

    def start_file_tracking(self):
        # Open the log file for reading
        try:
            self.file_handle = open(self.log_file, 'r', encoding='utf-8', errors='ignore')
            # Get the initial position
            self.log_position = self.file_handle.tell()
        except:
            logging.error(f"Error in opening file {self.log_file}: {e}")
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
                self.connection_manager.send_logs(encrypted_logs, self.log_file)

            # Check if the file has been rotated (size decreased)
            if os.path.exists(self.log_file) and os.path.getsize(self.log_file) < self.log_position:
                logging.info(f"Log file {self.log_file} has been rotated.")
                print("Log file has been rotated.")
                helper = self.log_file
                self.stop_file_tracking()
                # Update the log file path
                self.log_file = helper
                # Start tracking the new log file
                self.start_file_tracking()
                self.create_observer()
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

    def send_initial_logs(self, num_logs_to_send):
        if self.file_handle is None:
            self.start_file_tracking()
        
        """
        # Move the file pointer to the end to calculate the total number of logs
        self.file_handle.seek(0, os.SEEK_END)
        total_logs = self.file_handle.tell()

        # Calculate the offset to start reading from to get the last X logs
        start_offset = max(0, total_logs - num_logs_to_send)
        self.file_handle.seek(start_offset)
        """
        self.file_handle.seek(0)
        initial_logs = []
        for line in self.file_handle:
            initial_logs.append(line.strip())
        
        self.log_position = self.file_handle.tell()
        for log in initial_logs:
            encrypted_logs = encrypt_logs(log, self.encryption_key)
            self.connection_manager.send_logs(encrypted_logs, self.log_file)
            self.log_count = self.log_count + 1
            print(log)

    def create_observer(self):
        directory = os.path.dirname(self.log_file)
        if os.path.exists(directory):
            self.observer = Observer()
            self.observer.schedule(self, directory)
            self.observer.start()
            logging.info(f"Observer created for file {directory}.")
            print("hi")
        else:
            logging.error(f"Directory {directory} does not exist.")
            print(f"Directory {directory} does not exist.")
    
    def log_count_to_itself(self):
        if not self.log_count == 0:
            logging.info(f"{self.log_count} Logs sent successfully over {self.protocol} from file {self.log_file} to {self.destination_ip} on {self.destination_port}")
            self.log_count = 0
        time.sleep(self.time_to_sent_logs_on_agent)

def main():
    with open("cdlog.conf", 'r') as f:
        config = yaml.safe_load(f)

    # Extract configuration parameters
    log_directories = config["log_directories"]
    destination_ip = config["destination_ip"]
    destination_port = config["destination_port"]
    encryption_key = config["encryption_key"]
    transport_protocol = config["transport_protocol"]
    time_to_sent_logs_on_agent = config["time_to_sent_logs_on_agent"]

    global logs_counter

    # Create connection manager
    connection_manager = ConnectionManager(destination_ip, destination_port, transport_protocol)
    #connection_manager.socket.send("hello".encode())
    # Create handlers for each log file
    handlers = []  # Store handlers for sending initial logs later
    for log_dir in log_directories:
        directory = log_dir["directory"]
        excludes = log_dir["exclude"]
        num_logs_to_send = log_dir["num_logs_to_send"]
        formats = log_dir.get("formats", ["*"])  # Get formats if defined, otherwise use "*"

        # Assuming directory is the path to the directory or file
        if os.path.isdir(directory):
            # Handle as directory
            for root, _, files in os.walk(directory):
                # Create a new list excluding values in the 'excludes' list
                files_without_excludes = [x for x in files if x not in excludes]
                for file in files_without_excludes:
                    for format in formats:
                        if file.endswith(format) or format == "*":
                            log_file = os.path.join(root, file)
                            # Create a new observer for each log file
                            event_handler = LogFileHandler(log_file, connection_manager, encryption_key, time_to_sent_logs_on_agent)
                            event_handler.send_initial_logs(num_logs_to_send)
                            event_handler.create_observer()
                            handlers.append(event_handler)
        else:
            # Handle as file
            for format in formats:
                if directory.endswith(format) or format == "*":
                    log_file = directory
                    # Create a new observer for each log file
                    event_handler = LogFileHandler(log_file, connection_manager, encryption_key)
                    event_handler.send_initial_logs(num_logs_to_send)
                    event_handler.create_observer()
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
