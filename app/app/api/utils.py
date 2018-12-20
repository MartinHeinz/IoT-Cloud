from flask import jsonify


def http_json_response(success=True, code=200, **data):
    return jsonify(success=success, **data), code


def is_number(s):
    try:
        int(s)
        return True
    except ValueError:
        return False
