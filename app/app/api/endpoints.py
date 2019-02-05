from contextlib import suppress
from flask import request
from sqlalchemy import and_

from app.api import api
from app.api.utils import is_number
from app.app_setup import client, db
from app.auth.utils import require_api_token
from app.consts import DEVICE_TYPE_ID_MISSING_ERROR_MSG, DEVICE_TYPE_ID_INCORRECT_ERROR_MSG, \
    DEVICE_TYPE_DESC_MISSING_ERROR_MSG, \
    DEVICE_NAME_BI_MISSING_ERROR_MSG, DEVICE_NAME_MISSING_ERROR_MSG, DATA_RANGE_MISSING_ERROR_MSG, \
    DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG, \
    CORRECTNESS_HASH_MISSING_ERROR_MSG, DEVICE_ID_MISSING_ERROR_MSG, PUBLIC_KEY_MISSING_ERROR_MSG, \
    UNAUTHORIZED_USER_ERROR_MSG, NO_PUBLIC_KEY_ERROR_MSG, \
    DEVICE_NAME_INVALID_ERROR_MSG, DEVICE_PASSWORD_MISSING_ERROR_MSG, USER_MISSING_PASSWORD_HASH
from app.models.models import DeviceType, Device, DeviceData, UserDevice, User
from app.mqtt.utils import Payload
from app.utils import http_json_response, check_missing_request_argument, is_valid_uuid


@api.route('/publish', methods=['POST'])
def publish_message():
    message = request.args.get("ciphertext") + " " + request.args.get("tag")
    topic = request.args.get("topic")
    client.publish(topic, str(message))
    return http_json_response()


@api.route('/user/broker_register', methods=['POST'])
@require_api_token()
def register_to_broker():
    password_hash = request.args.get("password", None)
    user = User.get_by_access_token(request.args.get("access_token", ""))
    arg_check = check_missing_request_argument(
        (password_hash, USER_MISSING_PASSWORD_HASH))
    if arg_check is not True:
        return arg_check

    user.create_mqtt_creds_for_user(password_hash, db.session)
    db.session.commit()

    return http_json_response(**{"broker_id": str(user.id)})


@api.route('/device_type/create', methods=['POST'])
@require_api_token()
def create_device_type():
    description = request.args.get("description", None)
    correctness_hash = request.args.get("correctness_hash", None)
    user = User.get_by_access_token(request.args.get("access_token", ""))
    arg_check = check_missing_request_argument(
        (description, DEVICE_TYPE_DESC_MISSING_ERROR_MSG),
        (correctness_hash, CORRECTNESS_HASH_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check
    dt = DeviceType(description=description.encode(), owner=user, correctness_hash=correctness_hash)
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
    password_hash = request.args.get("password", None)  # TODO check if its correct format
    user = User.get_by_access_token(request.args.get("access_token", ""))
    arg_check = check_missing_request_argument(
        (device_type_id, DEVICE_TYPE_ID_MISSING_ERROR_MSG),
        (correctness_hash, CORRECTNESS_HASH_MISSING_ERROR_MSG),
        (name, DEVICE_NAME_MISSING_ERROR_MSG),
        (password_hash, DEVICE_PASSWORD_MISSING_ERROR_MSG),
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
    # noinspection PyArgumentList
    dv = Device(device_type_id=device_type_id,
                device_type=dt,
                owner=user,
                correctness_hash=correctness_hash,
                name=name.encode(),
                name_bi=name_bi)
    dv.create_mqtt_creds_for_device(password_hash, db.session)
    db.session.add(dv)
    db.session.commit()
    return http_json_response(**{'id': dv.id})


@api.route('/device/get', methods=['POST'])
@require_api_token()
def get_device_by_name():
    device_name_bi = request.args.get("name_bi", None)
    user = User.get_by_access_token(request.args.get("access_token", ""))
    if device_name_bi is None:
        return http_json_response(False, 400, **{"error": DEVICE_NAME_BI_MISSING_ERROR_MSG})
    devices = db.session.query(Device).filter(and_(Device.name_bi == device_name_bi, Device.owner == user))
    result = []
    for device in devices:
        d = device.as_dict()
        for k, v in d.items():
            if isinstance(v, bytes):
                d[k] = v.decode()
        result.append(d)
    return http_json_response(**{'devices': result})


@api.route('/data/get_by_num_range', methods=['POST'])
@require_api_token()
def get_data_by_num_range():
    lower_bound = request.args.get("lower", "")
    upper_bound = request.args.get("upper", "")
    device_id = request.args.get("device_id", None)

    arg_check = check_missing_request_argument((device_id, DEVICE_ID_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    if not is_number(lower_bound) and not is_number(upper_bound):
        return http_json_response(False, 400, **{"error": DATA_RANGE_MISSING_ERROR_MSG})

    with suppress(ValueError):
        lower_bound = int(lower_bound)
    with suppress(ValueError):
        upper_bound = int(upper_bound)

    data = []
    if isinstance(lower_bound, int) and isinstance(upper_bound, int):
        if -214748364800 <= lower_bound < upper_bound <= 214748364700:
            data = db.session.query(DeviceData).filter(and_(DeviceData.num_data > lower_bound,
                                                            DeviceData.num_data < upper_bound,
                                                            DeviceData.device_id == device_id)).all()
        else:
            return http_json_response(False, 400, **{"error": DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG})
    elif not isinstance(upper_bound, int) and isinstance(lower_bound, int):
        if -214748364800 <= lower_bound <= 214748364700:
            data = db.session.query(DeviceData).filter(and_(DeviceData.num_data > lower_bound,
                                                            DeviceData.device_id == device_id)).all()
        else:
            return http_json_response(False, 400, **{"error": DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG})

    elif not isinstance(lower_bound, int) and isinstance(upper_bound, int):
        if -214748364800 <= upper_bound <= 214748364700:
            data = db.session.query(DeviceData).filter(and_(DeviceData.num_data < upper_bound,
                                                            DeviceData.device_id == device_id)).all()
        else:
            return http_json_response(False, 400, **{"error": DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG})

    result = []
    for row in data:
        r = row.as_dict()
        for k, v in r.items():
            if isinstance(v, bytes):
                r[k] = v.decode()
        result.append(r)
    return http_json_response(**{'device_data': result})


@api.route('/data/get_device_data', methods=['POST'])
@require_api_token()
def get_device_data():
    device_id = request.args.get("device_id", None)
    access_token = request.args.get("access_token", "")

    arg_check = check_missing_request_argument((device_id, DEVICE_ID_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    if not is_number(device_id):
        return http_json_response(False, 400, **{"error": DEVICE_NAME_INVALID_ERROR_MSG})

    device_id = int(device_id)

    if not User.can_use_device(access_token, device_id):
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_ERROR_MSG})

    data = db.session.query(DeviceData).filter(DeviceData.device_id == device_id)

    result = []
    for row in data:
        r = row.as_dict()
        for k, v in r.items():
            if isinstance(v, bytes):
                r[k] = v.decode()
        result.append(r)

    return http_json_response(**{'device_data': result})


@api.route('/exchange_session_keys', methods=['POST'])
@require_api_token()
def exchange_session_keys():
    user_public_key_bytes = request.args.get("public_key", None)
    device_id = request.args.get("device_id", None)
    user_access_token = request.args.get("access_token", "")
    user = User.get_by_access_token(user_access_token)

    arg_check = check_missing_request_argument(
        (user_public_key_bytes, PUBLIC_KEY_MISSING_ERROR_MSG),
        (device_id, DEVICE_ID_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    if not User.can_use_device(user_access_token, device_id):
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_ERROR_MSG})

    # TODO save `user_public_key_bytes` to User Device Association Object?
    payload_bytes = bytes(Payload(
        user_public_key=user_public_key_bytes,
        user_id=user.id
    ))
    client.publish(f'server/{device_id}', f'"{payload_bytes.decode("utf-8")}"'.encode())
    return http_json_response()


@api.route('/retrieve_public_key', methods=['POST'])
@require_api_token()
def retrieve_public_key():
    device_id = request.args.get("device_id", None)
    user_access_token = request.args.get("access_token", "")
    user = User.get_by_access_token(user_access_token)

    arg_check = check_missing_request_argument(
        (device_id, DEVICE_ID_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    if not User.can_use_device(user_access_token, device_id):
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_ERROR_MSG})

    user_device = db.session.query(UserDevice) \
        .filter(and_(UserDevice.device_id == device_id,
                     UserDevice.user_id == user.id)).first()
    public_key = user_device.device_public_session_key

    if public_key:
        user_device.device_public_session_key = None
        user_device.added = None
        db.session.add(user_device)
        db.session.commit()
        return http_json_response(**{'device_public_key': public_key})
    return http_json_response(False, 400, **{"error": NO_PUBLIC_KEY_ERROR_MSG})
