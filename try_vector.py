import yaml
import json
import datetime
import re

class ParserManager:
    def __init__(self, parsers):
        self.parsers = parsers
        self.dict_of_parsers = {}
        self.load_parsers()
        self.actions_options = {"add_fields": self.add_fields, "remove_fields": self.remove_fields, "change_fields": self.change_fields}
        #self.manage_parser("parser 1")

    
    def load_parsers(self):
        for parser in self.parsers:
            parser_name = parser["name"]
            format = parser["format"]
            actions = parser["actions"]
            for action in actions:
                for key in action.keys():
                    #print(key)
                    pass
            self.dict_of_parsers.update({parser_name: {"format": format, "actions": actions}})
    
    def manage_parser(self, parser_name, log):
        current_parser = self.dict_of_parsers[parser_name]
        format = current_parser["format"]
        actions = current_parser["actions"]
        for action in actions:
            for key in action.keys():
                log = self.actions_options[key](action.values(), format, log)
        return log
    
    def add_fields(self, fields, format, log):
        fields = list(fields)[0]["fields"]
        for field in fields:
            keys = list(field.keys())
            values_of_field = field[keys[0]]
            name_of_field = keys[0]

            if "value_is_function" in keys:
                value_is_function = field["value_is_function"]
            else:
                value_is_function = False

            if value_is_function:
                values_of_field = eval(values_of_field)

            if format.lower() == "json":
                log = json.loads(log)
                log[name_of_field] = str(values_of_field)
                updated_json_log = json.dumps(log)
                log = updated_json_log
                print(log)
            
            elif format.lower() == "syslog":
                log = f"{log} {name_of_field}={values_of_field}"
                print(log)
        
        return log

    def remove_fields(self, fields, format, log):
        fields = list(fields)[0]["fields"]
        for field in fields:
            if format.lower() == "json":
                
                log = json.loads(log)
                log.pop(field, None)
                updated_json_log = json.dumps(log)
                log = updated_json_log
                print(log)
            
            elif format.lower() == "syslog":
                # Regular expression pattern to match the field
                pattern = f"{field}=[^ ]*"
                
                # Remove the field using regular expression substitution
                updated_message = re.sub(pattern, '', log)
                updated_message = re.sub('  ', ' ', updated_message)
                
                log = updated_message.strip()
                print(log)
        return log


    def change_fields(self, fields, format, log):
        fields = list(fields)[0]["fields"]
        for field in fields:
            keys = list(field.keys())
            values_of_field = field[keys[0]]
            name_of_field = keys[0]
            if "value_is_function" in keys:
                value_is_function = field["value_is_function"]
            else:
                value_is_function = False

            if format.lower() == "json":
                log = json.loads(log)
                if value_is_function:
                    values_of_field = eval(values_of_field)
                log[name_of_field] = str(values_of_field)
                updated_json_log = json.dumps(log)
                log = updated_json_log
                print(log)
            
            elif format.lower() == "syslog":
                # Regular expression pattern to match the field
                pattern = f"{name_of_field}=[^ ]*"
                
                # Remove the field using regular expression substitution
                updated_message = re.sub(pattern, f"{name_of_field}={values_of_field}", log)
                
                log = updated_message.strip()
                print(log)
        return log


def main():
    with open("copy_of_cdlog.conf", 'r') as f:
        config = yaml.safe_load(f)
    parsers = config.get('parsers', [])
    json_log = '{"timestamp": "2024-04-30T12:00:00", "message": "This is a sample log"}'
    syslog_log = 'This is a syslog message field1=value1 field2=value2 field3=value3'
    parser_manager = ParserManager(parsers)
    parser_manager.manage_parser('parser 2', syslog_log)

if __name__ == "__main__":
    main()