from contextlib import suppress
from flask import request
from sqlalchemy import and_

from app.api import api
from app.app_setup import client, db
from app.auth.utils import require_api_token
from app.consts import DEVICE_TYPE_ID_MISSING_ERROR_MSG, DEVICE_TYPE_ID_INCORRECT_ERROR_MSG, \
    DEVICE_TYPE_DESC_MISSING_ERROR_MSG, \
    DEVICE_NAME_BI_MISSING_ERROR_MSG, DEVICE_NAME_MISSING_ERROR_MSG, DATA_RANGE_MISSING_ERROR_MSG, \
    DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG, \
    CORRECTNESS_HASH_MISSING_ERROR_MSG, DEVICE_ID_MISSING_ERROR_MSG, PUBLIC_KEY_MISSING_ERROR_MSG, \
    UNAUTHORIZED_USER_ERROR_MSG, NO_PUBLIC_KEY_ERROR_MSG, \
    DEVICE_NAME_INVALID_ERROR_MSG, DEVICE_PASSWORD_MISSING_ERROR_MSG, USER_MISSING_PASSWORD_HASH, \
    ACTION_NAME_MISSING_ERROR_MSG, \
    ACTION_NAME_BI_MISSING_ERROR_MSG, ACTION_BI_INVALID_ERROR_MSG, NOT_REGISTERED_WITH_BROKER_ERROR_MSG, \
    INVALID_BROKER_PASSWORD_ERROR_MSG, \
    SCENE_DESC_MISSING_ERROR_MSG, SCENE_NAME_MISSING_ERROR_MSG, SCENE_NAME_BI_MISSING_ERROR_MSG, \
    INVALID_SCENE_OR_ACTION_BI_ERROR_MSG, \
    UNAUTHORIZED_USER_SCENE_ERROR_MSG, ACTION_ALREADY_PRESENT_ERROR_MSG, INVALID_SCENE_BI_ERROR_MSG, \
    AUTH_USER_ID_MISSING_ERROR_MSG, AUTH_USER_ID_INVALID_ERROR_MSG, AUTH_USER_ALREADY_AUTHORIZED_ERROR_MSG, \
    REVOKE_USER_ID_MISSING_ERROR_MSG, REVOKE_USER_ID_INVALID_ERROR_MSG, REVOKE_USER_NOT_AUTHORIZED_ERROR_MSG
from app.models.models import DeviceType, Device, DeviceData, UserDevice, User, Scene, Action
from app.mqtt.utils import Payload
from app.utils import http_json_response, check_missing_request_argument, is_valid_uuid, format_topic, validate_broker_password, is_number, create_payload


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

    if not validate_broker_password(password_hash):
        return http_json_response(False, 400, **{"error": INVALID_BROKER_PASSWORD_ERROR_MSG})

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
    password_hash = request.args.get("password", None)
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

    if not user.is_registered_with_broker:
        return http_json_response(False, 400, **{"error": NOT_REGISTERED_WITH_BROKER_ERROR_MSG})
    if not validate_broker_password(password_hash):
        return http_json_response(False, 400, **{"error": INVALID_BROKER_PASSWORD_ERROR_MSG})
    ud = UserDevice()
    # noinspection PyArgumentList
    dv = Device(device_type_id=device_type_id,
                device_type=dt,
                owner=user,
                owner_id=user.id,
                correctness_hash=correctness_hash,
                name=name.encode(),
                name_bi=name_bi)
    ud.device = dv
    with db.session.no_autoflush:
        user.devices.append(ud)
    dv.create_mqtt_creds_for_device(password_hash, db.session)
    user.add_acls_for_device(dv.id)
    db.session.add(dv)
    db.session.commit()
    return http_json_response(**{'id': dv.id})


@api.route('/scene/create', methods=['POST'])
@require_api_token()
def create_scene():
    name = request.args.get("name", None)
    description = request.args.get("description", None)
    name_bi = request.args.get("name_bi", None)
    correctness_hash = request.args.get("correctness_hash", None)
    arg_check = check_missing_request_argument(
        (name, SCENE_NAME_MISSING_ERROR_MSG),
        (description, SCENE_DESC_MISSING_ERROR_MSG),
        (name_bi, SCENE_NAME_BI_MISSING_ERROR_MSG),
        (correctness_hash, CORRECTNESS_HASH_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check
    sc = Scene(name=name.encode(),
               name_bi=name_bi,
               description=description.encode(),
               correctness_hash=correctness_hash)
    db.session.add(sc)
    db.session.commit()
    return http_json_response()


@api.route('/scene/add_action', methods=['POST'])
@require_api_token()
def add_scene_action():
    scene_name_bi = request.args.get("scene_name_bi", None)
    action_name_bi = request.args.get("action_name_bi", None)
    access_token = request.args.get("access_token", "")
    user = User.get_by_access_token(access_token)

    arg_check = check_missing_request_argument(
        (scene_name_bi, SCENE_NAME_BI_MISSING_ERROR_MSG),
        (action_name_bi, ACTION_NAME_BI_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    sc = Scene.get_by_name_bi(scene_name_bi)
    ac = Action.get_by_name_bi(action_name_bi)

    if sc is None or ac is None:
        return http_json_response(False, 400, **{"error": INVALID_SCENE_OR_ACTION_BI_ERROR_MSG})

    if not User.can_use_device(access_token, ac.device_id):
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_ERROR_MSG})

    if sc.owner is not None and sc.owner != user:
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_SCENE_ERROR_MSG})

    if sc.already_present(ac):
        return http_json_response(False, 400, **{"error": ACTION_ALREADY_PRESENT_ERROR_MSG})
    sc.actions.append(ac)
    db.session.add(sc)
    db.session.commit()

    return http_json_response()


@api.route('/device/set_action', methods=['POST'])
@require_api_token()
def set_device_action():
    device_id = request.args.get("device_id", None)
    correctness_hash = request.args.get("correctness_hash", None)
    name = request.args.get("name", None)
    name_bi = request.args.get("name_bi", None)
    access_token = request.args.get("access_token", "")
    user = User.get_by_access_token(access_token)

    arg_check = check_missing_request_argument(
        (device_id, DEVICE_ID_MISSING_ERROR_MSG),
        (correctness_hash, CORRECTNESS_HASH_MISSING_ERROR_MSG),
        (name, ACTION_NAME_MISSING_ERROR_MSG),
        (name_bi, ACTION_NAME_BI_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    if not user.is_registered_with_broker:
        return http_json_response(False, 400, **{"error": NOT_REGISTERED_WITH_BROKER_ERROR_MSG})
    if not User.can_use_device(access_token, device_id):
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_ERROR_MSG})

    dv = Device.get_by_id(device_id)
    with db.session.no_autoflush:
        dv.add_action(name.encode(), name_bi, correctness_hash)
    db.session.add(dv)
    db.session.commit()

    return http_json_response()


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
    client.publish(f'server/d:{device_id}/', f'"{payload_bytes.decode("utf-8")}"'.encode())
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


@api.route('/device/action', methods=['POST'])
@require_api_token()
def trigger_action():
    device_id = request.args.get("device_id", None)
    name_bi = request.args.get("name_bi", None)
    access_token = request.args.get("access_token", "")
    user = User.get_by_access_token(access_token)

    arg_check = check_missing_request_argument(
        (device_id, DEVICE_ID_MISSING_ERROR_MSG),
        (name_bi, ACTION_NAME_BI_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    if not User.can_use_device(access_token, device_id):
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_ERROR_MSG})

    dv = Device.get_by_id(device_id)
    topic = format_topic(user.mqtt_creds.username, dv.mqtt_creds.username)
    ac = Device.get_action_by_bi(device_id, name_bi)
    if ac is None:
        return http_json_response(False, 400, **{"error": ACTION_BI_INVALID_ERROR_MSG})
    payload = create_payload(user.mqtt_creds.username, {"action": ac.name.decode("utf-8")})
    client.publish(topic, payload)  # TODO encrypt with `shared key`
    return http_json_response()


@api.route('/scene/trigger', methods=['POST'])
@require_api_token()
def trigger_scene():
    name_bi = request.args.get("name_bi", None)
    access_token = request.args.get("access_token", "")
    user = User.get_by_access_token(access_token)

    arg_check = check_missing_request_argument(
        (name_bi, ACTION_NAME_BI_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    if not user.is_registered_with_broker:
        return http_json_response(False, 400, **{"error": NOT_REGISTERED_WITH_BROKER_ERROR_MSG})

    sc = Scene.get_by_name_bi(name_bi)
    if sc is None:
        return http_json_response(False, 400, **{"error": INVALID_SCENE_BI_ERROR_MSG})

    if sc.owner is not None and sc.owner != user:
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_SCENE_ERROR_MSG})

    for ac in sc.actions:
        payload = create_payload(user.mqtt_creds.username, {"action": ac.name.decode("utf-8")})
        topic = format_topic(user.mqtt_creds.username, ac.device.mqtt_creds.username)
        client.publish(topic, payload)

    return http_json_response()


@api.route('/device/authorize', methods=['POST'])
@require_api_token()
def authorize_user():
    device_id = request.args.get("device_id", None)
    auth_user_id = request.args.get("auth_user_id", None)  # ID of user to be authorized
    access_token = request.args.get("access_token", "")
    auth_user = User.get_by_id(auth_user_id)

    arg_check = check_missing_request_argument(
        (device_id, DEVICE_ID_MISSING_ERROR_MSG),
        (auth_user_id, AUTH_USER_ID_MISSING_ERROR_MSG),
        (None if auth_user is None or auth_user.access_token == access_token else auth_user, AUTH_USER_ID_INVALID_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    if not User.can_use_device(access_token, device_id):
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_ERROR_MSG})

    device = Device.get_by_id(device_id)

    if not auth_user.is_registered_with_broker:
        return http_json_response(False, 400, **{"error": NOT_REGISTERED_WITH_BROKER_ERROR_MSG})

    if next((ud for ud in device.users if ud.user_id == auth_user.id), None) is not None:
        return http_json_response(False, 400, **{"error": AUTH_USER_ALREADY_AUTHORIZED_ERROR_MSG})

    ud = UserDevice()
    ud.device = device
    ud.user = auth_user
    db.session.add(ud)
    auth_user.add_acls_for_device(device_id)

    db.session.commit()

    return http_json_response()


@api.route('/device/revoke', methods=['POST'])
@require_api_token()
def revoke_user():
    device_id = request.args.get("device_id", None)
    revoke_user_id = request.args.get("revoke_user_id", None)  # ID of user to be revoked
    access_token = request.args.get("access_token", "")
    user_to_revoke = User.get_by_id(revoke_user_id)

    arg_check = check_missing_request_argument(
        (device_id, DEVICE_ID_MISSING_ERROR_MSG),
        (revoke_user_id, REVOKE_USER_ID_MISSING_ERROR_MSG),
        (None if user_to_revoke is None or user_to_revoke.access_token == access_token else user_to_revoke, REVOKE_USER_ID_INVALID_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    if not User.can_use_device(access_token, device_id):
        return http_json_response(False, 400, **{"error": UNAUTHORIZED_USER_ERROR_MSG})

    device = Device.get_by_id(device_id)

    if next((ud for ud in device.users if ud.user_id == user_to_revoke.id), None) is None:
        return http_json_response(False, 400, **{"error": REVOKE_USER_NOT_AUTHORIZED_ERROR_MSG})

    ud_to_remove = UserDevice.get_by_ids(int(device_id), user_to_revoke.id)

    device.users.remove(ud_to_remove)
    db.session.add(device)
    user_to_revoke.remove_acls_for_device(device_id)
    db.session.add(user_to_revoke)
    db.session.commit()

    return http_json_response()
