import os
import time
import yaml
import threading
import socket
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import psycopg2

# Connect to the PostgreSQL database
conn = psycopg2.connect(
    dbname="ofek_db",
    user="postgres",
    password="Aa123456",
    host="127.0.0.1",
    port="5432"
)

# Create a cursor object
cur = conn.cursor()

# Execute a SELECT query
cur.execute("SELECT * FROM your_table_name")

# Fetch all rows from the result set
rows = cur.fetchall()

# Print the rows
for row in rows:
    print(row)

# Close the cursor and connection
cur.close()
conn.close()


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