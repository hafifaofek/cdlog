import yaml

class ParserManager:
    def __init__(self, parsers):
        self.parsers = parsers
        self.dict_of_parsers = {}
        self.load_parsers()
        self.actions_options = {"add_fields": self.add_fields, "remove_fields": self.remove_fields, "change_fields": self.change_fields}
        self.manage_parser("parser 1")

    
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
    
    def manage_parser(self, parser_name):
        current_parser = self.dict_of_parsers[parser_name]
        format = current_parser["format"]
        actions = current_parser["actions"]
        for action in actions:
            for key in action.keys():
                self.actions_options[key](action.values())
    
    def add_fields(self, fields):
        fields = list(fields)[0]["fields"]
        print(fields)
        for field in fields:
            keys = list(field.keys())
            values_of_field = field[keys[0]]
            name_of_field = keys[0]
            if "value_is_function" in keys:
                value_is_function = field["value_is_function"]
                print(value_is_function)
            print(f"{name_of_field} - {values_of_field}")
            

    def remove_fields(self, fields):
        fields = list(fields)[0]["fields"]
        for field in fields:
            print(field)


    def change_fields(self, fields):
        fields = list(fields)[0]["fields"]
        for field in fields:
            keys = list(field.keys())
            values_of_field = field[keys[0]]
            name_of_field = keys[0]
            if "value_is_function" in keys:
                value_is_function = field["value_is_function"]
                print(value_is_function)
            print(f"{name_of_field} - {values_of_field}")


def main():
    with open("copy_of_cdlog.conf", 'r') as f:
        config = yaml.safe_load(f)
    parsers = config.get('parsers', [])
    parser_manager = ParserManager(parsers)

if __name__ == "__main__":
    main()