import json
import csv
from io import StringIO

def json_to_csv(json_log):
    # Extract headers from JSON keys
    headers = list(json_log.keys())

    # Create a StringIO object to hold CSV data
    csv_buffer = StringIO()

    # Use CSV DictWriter to write to the StringIO buffer
    writer = csv.DictWriter(csv_buffer, fieldnames=headers)

    # Write headers to CSV buffer
    writer.writeheader()

    # Write JSON log data to CSV buffer
    writer.writerow(json_log)

    # Get CSV data from the buffer
    csv_data = csv_buffer.getvalue()

    # Close the buffer
    csv_buffer.close()

    return csv_data

# Example JSON log (replace with your actual JSON log)
json_log = {
    "timestamp": "2024-04-30T12:34:56",
    "level": "INFO",
    "message": "This is a log message."
}


# Convert JSON log to CSV format
#csv_log = json_to_csv(json_log)
import re
from datetime import datetime

former_format = "%Y-%m-%d %H:%M:%S.%f"
new_format = "%Y-%m-%d %H:%M"
log = "<134>2024-04-30 10:15:23.000000 myhost myapp[12345]: This is a sample syslog message."

# Parse the old timestamp string into a datetime object
escaped_former_format = re.escape(former_format)
syslog_regex = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}"
old_timestamp_match = re.search(syslog_regex, log)
old_timestamp = old_timestamp_match.group()
print(old_timestamp)
parsed_timestamp = datetime.strptime(old_timestamp, former_format)
new_timestamp = parsed_timestamp.strftime(new_format)
print(parsed_timestamp)
new_log_line = re.sub(syslog_regex, str(new_timestamp), log)
print(new_log_line)
#new_syslog = re.sub(syslog_regex, f"<\g<1>>{new_timestamp}\g<2>", log)
#print(new_syslog)

