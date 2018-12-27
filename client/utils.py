import json


def json_string_with_bytes_to_dict(value):
    return json.loads(value.replace("\\", "\\\\"), strict=False)
