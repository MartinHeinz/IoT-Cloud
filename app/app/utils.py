import json

from flask import jsonify


def http_json_response(success=True, code=200, **data):
    return jsonify(success=success, **data), code


def bytes_to_json(value):
    string_value = value.decode("utf8").replace("'", '"')
    return json.loads(string_value)


def check_missing_request_argument(*pairs):
    for pair in pairs:
        if pair[0] is None:
            return http_json_response(False, 400, **{"error": pair[1]})
    return True
