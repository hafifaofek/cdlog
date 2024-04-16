import os
import time
import yaml
import threading
import socket
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Function to send logs to a remote server
def send_logs(logs, ip, port):
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect to the server
        s.connect((ip, port))
        # Send each log
        for log in logs:
            s.sendall(log.encode())
        # Close the connection
        s.close()
        print("Logs sent successfully!")
    except Exception as e:
        print("Error:", e)

def print_logs(logs):
    for log in logs:
        print(log)

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file, destination_ip, destination_port):
        super(LogFileHandler, self).__init__()
        self.log_file = log_file
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.log_position = 0
        self.file_handle = open(log_file, 'r')

    def on_modified(self, event):
        if not event.is_directory and event.src_path == self.log_file:
            new_logs = self.collect_new_logs()
            if new_logs:
                print_logs(new_logs)
                # Send new logs to the server
                #send_logs(new_logs, self.destination_ip, self.destination_port)

    def collect_new_logs(self):
        new_logs = []
        self.file_handle.seek(self.log_position)
        for line in self.file_handle:
            new_logs.append(line.strip())
        self.log_position = self.file_handle.tell()
        return new_logs

def main():
    with open("cdlog.conf", 'r') as f:
        config = yaml.safe_load(f)

    # Extract configuration parameters
    log_directories = config["log_directories"]
    destination_ip = config["destination_ip"]
    destination_port = config["destination_port"]
    files_formats = config["file_formats"]

    # Create observer and event handler for each log file
    observers = []
    for log_directory in log_directories:
        for root, _, files in os.walk(log_directory):
            for file in files:
                for format in files_formats:
                    if file.endswith(format):
                        log_file = os.path.join(root, file)
                        event_handler = LogFileHandler(log_file, destination_ip, destination_port)
                        observer = Observer()
                        observer.schedule(event_handler, log_directory)
                        observer.start()
                        observers.append(observer)

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