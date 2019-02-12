import json
import re
from uuid import UUID

from flask import jsonify


def http_json_response(success=True, code=200, **data):
    return jsonify(success=success, **data), code


def bytes_to_json(value):
    value = value.decode("utf8")
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    string_value = value.replace("'", '"').replace("\n", "\\n")
    return json.loads(string_value)


def check_missing_request_argument(*pairs):
    for pair in pairs:
        if pair[0] is None:
            return http_json_response(False, 400, **{"error": pair[1]})
    return True


def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        return False

    return str(uuid_obj) == uuid_to_test


def format_topic(src, dest, sender):
    if sender == "user":
        return f"u:{src}/d:{dest}/"
    elif sender == "device":
        return f"d:{src}/u:{dest}/"
    else:
        raise Exception("Invalid sender type.")


def validate_broker_password(pass_hash):
    return re.match(r'PBKDF2\$sha256\$\d+\$.{16}\$.{32}', pass_hash) is not None


def is_number(s):
    try:
        int(s)
        return True
    except (ValueError, TypeError):
        return False


def create_payload(user_id, pairs):
    payload = {}
    for k, v in pairs.items():
        payload[f'"{k}"'] = f'"{pairs[k]}"'
    payload['"user_id"'] = f'"{user_id}"'
    return f'"{json.dumps(payload)}"'
