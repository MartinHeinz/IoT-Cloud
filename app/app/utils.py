import json
from uuid import UUID

from flask import jsonify
from sqlalchemy import and_

from app.app_setup import db
from app.models.models import User, UserDevice


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


def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        return False

    return str(uuid_obj) == uuid_to_test


def get_user_by_id(user_id):
    return db.session.query(User).filter(User.id == user_id).first()


def get_user_device_by_ids(device_id, user_id):
    return db.session.query(UserDevice) \
        .filter(and_(UserDevice.device_id == device_id,
                     UserDevice.user_id == user_id)).first()
