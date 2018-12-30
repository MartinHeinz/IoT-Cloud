from contextlib import suppress
from flask import request
from sqlalchemy import and_

from app.api import api
from app.api.utils import is_number, get_user_by_access_token
from app.app_setup import client, db
from app.auth.utils import require_api_token
from app.models.models import DeviceType, Device, DeviceData
from app.utils import http_json_response, check_missing_request_argument, is_valid_uuid

DEVICE_TYPE_ID_MISSING_ERROR_MSG = 'Missing device type id.'
DEVICE_TYPE_ID_INCORRECT_ERROR_MSG = 'Incorrect device type id.'
DEVICE_TYPE_DESC_MISSING_ERROR_MSG = 'Missing device type description.'
DEVICE_NAME_BI_MISSING_ERROR_MSG = 'Missing device Blind Index.'
DEVICE_NAME_MISSING_ERROR_MSG = 'Missing device Name.'
DATA_RANGE_MISSING_ERROR_MSG = 'Missing upper and lower range for query.'
DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG = 'Value out of OPE output range.'
CORRECTNESS_HASH_MISSING_ERROR_MSG = 'Correctness Hash needs to be provided.'


@api.route('/publish', methods=['POST'])
def publish_message():
    message = request.args.get("ciphertext") + " " + request.args.get("tag")
    topic = request.args.get("topic")
    client.publish(topic, str(message))
    return http_json_response()


@api.route('/device_type/create', methods=['POST'])
@require_api_token()
def create_device_type():
    description = request.args.get("description", None)
    correctness_hash = request.args.get("correctness_hash", None)
    user = get_user_by_access_token(request.args.get("access_token", ""))
    arg_check = check_missing_request_argument(
        (description, DEVICE_TYPE_DESC_MISSING_ERROR_MSG),
        (correctness_hash, CORRECTNESS_HASH_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check
    dt = DeviceType(description=description, owner=user, correctness_hash=correctness_hash)
    db.session.add(dt)
    db.session.commit()
    return http_json_response(**{"type_id": str(dt.type_id)})


@api.route('/device/create', methods=['POST'])
@require_api_token()
def create_device():
    device_type_id = request.args.get("type_id", None)
    correctness_hash = request.args.get("correctness_hash", None)
    name = request.args.get("name", None)
    name_bi = request.args.get("name_bi", None)
    user = get_user_by_access_token(request.args.get("access_token", ""))
    arg_check = check_missing_request_argument(
        (device_type_id, DEVICE_TYPE_ID_MISSING_ERROR_MSG),
        (correctness_hash, CORRECTNESS_HASH_MISSING_ERROR_MSG),
        (name, DEVICE_NAME_MISSING_ERROR_MSG),
        (name_bi, DEVICE_NAME_BI_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check
    dt = None
    try:
        if is_valid_uuid(device_type_id):
            dt = db.session.query(DeviceType).filter(DeviceType.type_id == device_type_id).first()
    finally:
        if dt is None:
            return http_json_response(False, 400, **{"error": DEVICE_TYPE_ID_INCORRECT_ERROR_MSG})
    dv = Device(device_type_id=device_type_id,
                device_type=dt,
                owner=user,
                correctness_hash=correctness_hash,
                name=name,
                name_bi=name_bi)
    db.session.add(dv)
    db.session.commit()
    return http_json_response(**{'id': dv.id})


@api.route('/device/get', methods=['POST'])
@require_api_token()
def get_device_by_name():
    device_name_bi = request.args.get("name_bi", None)
    user = get_user_by_access_token(request.args.get("access_token", ""))
    if device_name_bi is None:
        return http_json_response(False, 400, **{"error": DEVICE_NAME_BI_MISSING_ERROR_MSG})
    devices = db.session.query(Device).filter(and_(Device.name_bi == device_name_bi, Device.owner == user))
    result = []
    for device in devices:
        result.append(device.as_dict())
    return http_json_response(**{'devices': result})


@api.route('/data/get_time_range', methods=['POST'])
@require_api_token()
def get_data_by_time_range():
    lower_bound = request.args.get("lower", "")
    upper_bound = request.args.get("upper", "")
    user = get_user_by_access_token(request.args.get("access_token", ""))

    if not is_number(lower_bound) and not is_number(upper_bound):
        return http_json_response(False, 400, **{"error": DATA_RANGE_MISSING_ERROR_MSG})

    with suppress(ValueError):
        lower_bound = int(lower_bound)
    with suppress(ValueError):
        upper_bound = int(upper_bound)

    data = []
    if type(lower_bound) is int and type(upper_bound) is int:
        if 0 <= lower_bound < upper_bound <= 2147483647:
            data = db.session.query(DeviceData).filter(and_(DeviceData.num_data > lower_bound, DeviceData.num_data < upper_bound, DeviceData.device_id.in_(d.id for d in user.owned_devices))).all()
        else:
            return http_json_response(False, 400, **{"error": DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG})
    elif type(upper_bound) is not int and type(lower_bound) is int:
        if 0 <= lower_bound <= 2147483647:
            data = db.session.query(DeviceData).filter(and_(DeviceData.num_data > lower_bound, DeviceData.device_id.in_(d.id for d in user.owned_devices))).all()
        else:
            return http_json_response(False, 400, **{"error": DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG})

    elif type(lower_bound) is not int and type(upper_bound) is int:
        if 0 <= upper_bound <= 2147483647:
            data = db.session.query(DeviceData).filter(and_(DeviceData.num_data < upper_bound, DeviceData.device_id.in_(d.id for d in user.owned_devices))).all()
        else:
            return http_json_response(False, 400, **{"error": DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG})

    result = []
    for row in data:
        result.append(row.as_dict())
        result[-1]["data"] = result[-1]["data"].decode("utf-8")
    return http_json_response(**{'device_data': result})
