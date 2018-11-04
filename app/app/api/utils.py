import json


def http_json_response(success=True, code=200, **data):
	return json.dumps({'success': success, **data}), code, {'ContentType': 'application/json'}
