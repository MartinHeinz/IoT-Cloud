from flask import request
from app.api import api
from app.api.utils import http_json_response
from app.app_setup import client, db
from app.models.models import DeviceType, Device

DEVICE_TYPE_ID_MISSING_ERROR_MSG = 'Missing device type id.'
DEVICE_TYPE_ID_INCORRECT_ERROR_MSG = 'Incorrect device type id.'
DEVICE_TYPE_DESC_MISSING_ERROR_MSG = 'Missing device type description.'
DEVICE_NAME_BI_MISSING_ERROR_MSG = 'Missing device Blind Index.'


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
    try:  # TODO do check whether UUID is valid (test_api_dv_create)
        dt = db.session.query(DeviceType).filter(DeviceType.type_id == device_type_id).first()
    finally:  # TODO change to except and provide specific exception?
        if dt is None:
            return http_json_response(False, 400, **{"error": DEVICE_TYPE_ID_INCORRECT_ERROR_MSG})
    dv = Device(device_type_id=device_type_id, device_type=dt)
    db.session.add(dv)
    db.session.commit()
    return http_json_response(**{'id': dv.id})


@api.route('/device/get', methods=['POST'])
def get_device_by_name():  # TODO limit to only users devices, when auth is implemented
    device_name_bi = request.args.get("name_bi", None)
    print(device_name_bi, flush=True)
    if device_name_bi is None:
        return http_json_response(False, 400, **{"error": DEVICE_NAME_BI_MISSING_ERROR_MSG})
    devices = db.session.query(Device).filter(Device.name_bi == device_name_bi)
    result = []
    for device in devices:
        result = device.as_dict()
    print(result, flush=True)
    return http_json_response(**{'devices': result})
