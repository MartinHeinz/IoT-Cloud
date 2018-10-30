import json

from flask import request

from app.api import api
from app.app_setup import client


@api.route('/publish', methods=['POST'])
def publish_message():
	message = request.args["ciphertext"] + " " + request.args["tag"]
	client.publish(request.args["topic"], str(message))
	return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}
