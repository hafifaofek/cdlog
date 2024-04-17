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

# Function to send encrypted logs over UDP
def send_logs_udp(logs, ip, port):
    try:
        # Create a UDP socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Send each encrypted log
        for log in logs:
            s.sendto(log, (ip, port))
        # Close the socket
        s.close()
        print("Logs sent successfully over UDP!")
    except Exception as e:
        print("Error:", e)

# Function to send encrypted logs over TCP with TLS
def send_logs_tcp_tls(logs, ip, port):
    try:
        # Create a TCP socket object
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        s = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=ip)
        # Connect to the server
        s.connect((ip, port))
        # Send each encrypted log
        for log in logs:
            s.sendall(log)
        # Close the connection
        s.close()
        print("Logs sent successfully over TCP with TLS!")
    except Exception as e:
        print("Error:", e)

def print_logs(logs):
    for log in logs:
        print(log)

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file, destination_ip, destination_port, encryption_key, transport_protocol):
        super(LogFileHandler, self).__init__()
        self.log_file = log_file
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.encryption_key = encryption_key
        self.transport_protocol = transport_protocol
        self.log_position = 0
        self.file_handle = open(log_file, 'r', encoding='utf-8', errors='ignore')

    def on_modified(self, event):
        if not event.is_directory and event.src_path == self.log_file:
            new_logs = self.collect_new_logs()
            if new_logs:
                print_logs(new_logs)
                # Encrypt new logs
                encrypted_logs = encrypt_logs(new_logs, self.encryption_key)
                # Send encrypted logs based on the transport protocol
                if self.transport_protocol == "UDP":
                    pass
                    #send_logs_udp(encrypted_logs, self.destination_ip, self.destination_port)
                elif self.transport_protocol == "tcp_tls":
                    pass
                    #send_logs_tcp_tls(encrypted_logs, self.destination_ip, self.destination_port)

    def collect_new_logs(self):
        new_logs = []
        self.file_handle.seek(self.log_position)
        for line in self.file_handle:
            new_logs.append(line.strip())
        self.log_position = self.file_handle.tell()
        return new_logs

    def send_initial_logs(self):
        self.file_handle.seek(0)
        initial_logs = []
        for line in self.file_handle:
            initial_logs.append(line.strip())
        #encrypted_initial_logs = encrypt_logs(initial_logs, self.encryption_key)
        # Send the encrypted initial logs
        if self.transport_protocol == "UDP":
            pass
            #send_logs_udp(encrypted_initial_logs, self.destination_ip, self.destination_port)
        elif self.transport_protocol == "tcp_tls":
            pass
            #send_logs_tcp_tls(encrypted_initial_logs, self.destination_ip, self.destination_port)

def main():
    with open("cdlog.conf", 'r') as f:
        config = yaml.safe_load(f)

    # Extract configuration parameters
    log_directories = config["log_directories"]
    destination_ip = config["destination_ip"]
    destination_port = config["destination_port"]
    files_formats = config["file_formats"]
    encryption_key = config["encryption_key"]
    transport_protocol = config["transport_protocol"]

    # Create observer and event handler for each log file
    observers = []
    handlers = []  # Store handlers for sending initial logs later
    for log_directory in log_directories:
        for root, _, files in os.walk(log_directory):
            for file in files:
                for format in files_formats:
                    if file.endswith(format):
                        log_file = os.path.join(root, file)
                        event_handler = LogFileHandler(log_file, destination_ip, destination_port, encryption_key, transport_protocol)
                        observer = Observer()
                        observer.schedule(event_handler, log_directory)
                        observer.start()
                        observers.append(observer)
                        handlers.append(event_handler)
                        

    # Send initial logs for all files
    for handler in handlers:
        handler.send_initial_logs()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for observer in observers:
            observer.stop()
        for observer in observers:
            observer.join()

if __name__ == "__main__":
    main()
