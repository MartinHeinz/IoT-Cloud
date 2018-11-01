import json
from flask import request
from app.api import api
from app.app_setup import client, db
from app.models.models import DeviceType, Device


@api.route('/publish', methods=['POST'])
def publish_message():
	message = request.args["ciphertext"] + " " + request.args["tag"]
	client.publish(request.args["topic"], str(message))
	return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}


@api.route('/device_type/create', methods=['POST'])
def create_device_type():
	description = request.args.get("description", None)
	if description is None:
		return json.dumps({'success': False, 'error': 'Missing device type description.'}), 400, {'ContentType': 'application/json'}
	dt = DeviceType(description=description)
	db.session.add(dt)
	db.session.commit()
	return json.dumps({'success': True, 'type_id': str(dt.type_id)}), 200, {'ContentType': 'application/json'}


@api.route('/device/create', methods=['POST'])  # TODO write tests
def create_device():
	device_type_id = request.args.get("type_id", None)
	if device_type_id is None:
		return json.dumps({'success': False, 'error': 'Missing device type id.'}), 400, {'ContentType': 'application/json'}
	dt = None
	try:
		dt = db.session.query(DeviceType).filter(DeviceType.type_id == device_type_id).first()
	finally:
		if dt is None:
			return json.dumps({'success': False, 'error': 'Incorrect device type id.'}), 400, {'ContentType': 'application/json'}
	dv = Device(device_type_id=device_type_id, device_type=dt)
	db.session.add(dv)
	db.session.commit()
	return json.dumps({'success': True, 'id': dv.id}), 200, {'ContentType': 'application/json'}
