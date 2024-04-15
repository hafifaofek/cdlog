import socket
import os
import time
import yaml

# Function to collect new logs from log files
def collect_new_logs(log_directory, log_positions):
    new_logs = {}
    for log_file, position in log_positions.items():
        # Check if log file exists and is accessible
        if not os.path.isfile(log_file):
            continue
        try:
            with open(log_file, 'r') as f:
                f.seek(position)
                new_logs[log_file] = f.read()
                log_positions[log_file] = f.tell()
        except Exception as e:
            print(f"Error reading file '{log_file}':", e)
    return new_logs

# Function to send logs to a remote server
def send_logs(logs, ip, port):
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect to the server
        s.connect((ip, port))
        # Send each log
        for log in logs.values():
            s.sendall(log.encode())
        # Close the connection
        s.close()
        print("Logs sent successfully!")
    except Exception as e:
        print("Error:", e)

def print_logs(logs):
    for log in logs.values():
        print(log)

def main():
    with open("cdlog.conf", 'r') as f:
        config = yaml.safe_load(f)

    # Extract configuration parameters
    log_directory = config["log_directory"]
    destination_ip = config["destination_ip"]
    destination_port = config["destination_port"]
    files_formats = config["file_formats"]

    # Dictionary to store the last read positions of log files
    log_positions = {}

    # Initialize log positions
    for root, _, files in os.walk(log_directory):
        for file in files:
            for format in files_formats:
                if file.endswith(format):
                    log_positions[os.path.join(root, file)] = 0

    while True:
        # Collect new logs
        new_logs = collect_new_logs(log_directory, log_positions)
        print_logs(new_logs)
        # Send new logs to the server
        send_logs(new_logs, destination_ip, destination_port)
        # Wait for 60 seconds before sending logs again
        time.sleep(60)
if __name__ == "__main__":
    main()
