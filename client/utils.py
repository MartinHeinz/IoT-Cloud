import json


def json_string_with_bytes_to_dict(value):
    return json.loads(value.replace("\\", "\\\\"), strict=False)


def _create_payload(user_id, pairs):
    payload = {}
    for k, v in pairs.items():
        payload[f'"{k}"'] = f'"{pairs[k]}"'
    payload['"user_id"'] = user_id
    return f'"{json.dumps(payload)}"'
