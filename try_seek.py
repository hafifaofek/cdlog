import re
import json

def parse_syslog_to_json(syslog_message):
    # Define regular expression pattern to extract fields
    pattern = r'<(?P<priority>\d+)>\s*(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s*(?P<hostname>\S+)\s+(?P<app_name>\S+):\s(?P<message>.*)$'
    pattern = r'<(?P<priority>\d+)>\s*(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s*(?P<hostname>\S+)\s+(?P<app_name>\S+):\s(?P<message>.*)$'

    # Use regular expression to match the pattern
    match = re.match(pattern, syslog_message)

    if match:
        # Extract fields from the match object
        priority = match.group('priority')
        timestamp = match.group('timestamp')
        hostname = match.group('hostname')
        app_name = match.group('app_name')
        message = match.group('message')

        # Create a dictionary to hold the extracted fields
        syslog_json = {
            'priority': int(priority),  # Convert priority to integer
            'timestamp': timestamp,
            'hostname': hostname,
            'app_name': app_name,
        }

        # Split the message into key-value pairs
        message_pairs = message.split()
        print(message_pairs)
        for pair in message_pairs:
            key, value = pair.split(':', 1)  # Split key-value pair
            syslog_json[key] = value

        # Serialize the dictionary into a JSON string
        return json.dumps(syslog_json)
    else:
        return None

# Example usage
syslog_message = "<123> 2024-04-30 10:15:23.000000 hostname app_name: key1:value1 key2:value2 key3:value3"
#syslog_message = "<134>2024-04-30 10:15:23.000000 myhost myapp[12345]: This is a sample syslog message."
json_log = parse_syslog_to_json(syslog_message)
print(json_log)
