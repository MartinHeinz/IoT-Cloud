import json


def bytes_to_json(value):
    string_value = value.decode("utf8").replace("'", '"')
    return json.loads(string_value)
