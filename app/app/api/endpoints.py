from flask import request
from app.api import api
from app.api.utils import http_json_response
from app.app_setup import client, db
from app.models.models import DeviceType, Device

DEVICE_TYPE_ID_MISSING_ERROR_MSG = 'Missing device type id.'
DEVICE_TYPE_ID_INCORRECT_ERROR_MSG = 'Incorrect device type id.'
DEVICE_TYPE_DESC_MISSING_ERROR_MSG = 'Missing device type description.'


@api.route('/publish', methods=['POST'])
def publish_message():
    message = request.args.get("ciphertext") + " " + request.args.get("tag")
    topic = request.args.get("topic")
    client.publish(topic, str(message))
    return http_json_response()


@api.route('/device_type/create', methods=['POST'])
def create_device_type():
    description = request.args.get("description", None)
    if description is None:
        return http_json_response(False, 400, **{"error": DEVICE_TYPE_DESC_MISSING_ERROR_MSG})
    dt = DeviceType(description=description)
    db.session.add(dt)
    db.session.commit()
    return http_json_response(**{"type_id": str(dt.type_id)})


@api.route('/device/create', methods=['POST'])
def create_device():
    device_type_id = request.args.get("type_id", None)
    if device_type_id is None:
        return http_json_response(False, 400, **{"error": DEVICE_TYPE_ID_MISSING_ERROR_MSG})
    dt = None
    try:
        dt = db.session.query(DeviceType).filter(DeviceType.type_id == device_type_id).first()
    finally:  # TODO change to except and provide specific exception?
        if dt is None:
            return http_json_response(False, 400, **{"error": DEVICE_TYPE_ID_INCORRECT_ERROR_MSG})
    dv = Device(device_type_id=device_type_id, device_type=dt)
    db.session.add(dv)
    db.session.commit()
    return http_json_response(**{'id': dv.id})
