# -*- coding: utf-8 -*-
import base64
import json
import types
from unittest import mock
from unittest.mock import call
from uuid import UUID

from passlib.hash import bcrypt

from app.auth.utils import token_to_hash
from app.consts import DEVICE_TYPE_ID_MISSING_ERROR_MSG, DEVICE_TYPE_ID_INCORRECT_ERROR_MSG, \
    DEVICE_NAME_BI_MISSING_ERROR_MSG, DEVICE_NAME_MISSING_ERROR_MSG, \
    DATA_RANGE_MISSING_ERROR_MSG, DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG, CORRECTNESS_HASH_MISSING_ERROR_MSG, \
    SOMETHING_WENT_WRONG_MSG, DEVICE_ID_MISSING_ERROR_MSG, \
    DEVICE_PASSWORD_MISSING_ERROR_MSG, USER_MISSING_PASSWORD_HASH, \
    ACTION_NAME_MISSING_ERROR_MSG, \
    ACTION_NAME_BI_MISSING_ERROR_MSG, UNAUTHORIZED_USER_ERROR_MSG, ACTION_BI_INVALID_ERROR_MSG, \
    NOT_REGISTERED_WITH_BROKER_ERROR_MSG, \
    INVALID_BROKER_PASSWORD_ERROR_MSG, SCENE_NAME_MISSING_ERROR_MSG, SCENE_DESC_MISSING_ERROR_MSG, \
    SCENE_NAME_BI_MISSING_ERROR_MSG, \
    INVALID_SCENE_OR_ACTION_BI_ERROR_MSG, ACTION_ALREADY_PRESENT_ERROR_MSG, UNAUTHORIZED_USER_SCENE_ERROR_MSG, \
    INVALID_SCENE_BI_ERROR_MSG, AUTH_USER_ID_INVALID_ERROR_MSG, AUTH_USER_ID_MISSING_ERROR_MSG, \
    AUTH_USER_ALREADY_AUTHORIZED_ERROR_MSG, REVOKE_USER_ID_MISSING_ERROR_MSG, REVOKE_USER_ID_INVALID_ERROR_MSG, \
    REVOKE_USER_NOT_AUTHORIZED_ERROR_MSG, DEVICE_NAME_BI_INVALID_ERROR_MSG
from app.models.models import DeviceType, Device, User, Action, Scene, UserDevice
from app.app_setup import client as mqtt_client
from app.utils import is_valid_uuid, bytes_to_json, format_topic, validate_broker_password
from client.crypto_utils import encrypt, correctness_hash, triangle_wave, sawtooth_wave, square_wave, sine_wave, generate, \
    encrypt_row, instantiate_ope_cipher, decrypt_using_fernet_hex, decrypt_using_ope_hex, decrypt_using_abe_serialized_key

from .conftest import db, assert_got_error_from_post, assert_got_data_from_post, get_data_from_post, \
    assert_got_error_from_get, assert_got_data_from_get, get_data_from_get


def test_mqtt_client(app_and_ctx):
    assert mqtt_client._ssl is True


def test_index(client):
    response = client.get('/')
    assert "Hi from app!" in str(response.data)


def test_error_handler(client):
    response = client.post('/nonvalidurl', follow_redirects=False)
    assert response.status_code == 404
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == SOMETHING_WENT_WRONG_MSG


def test_publish(client):
    response = client.get('/publish')
    assert response.status_code == 200

    response = client.post('/publish', data=dict(
        topic="",
        message=""
    ), follow_redirects=False)
    assert response.status_code == 200

    response = client.post('/publish', data=dict(
        topic="flask_test",
        message="message"
    ), follow_redirects=False)
    assert response.status_code == 302


def test_api_publish(client):
    iv, ciphertext, tag = encrypt(
        b'f\x9c\xeb Lj\x13n\x84B\xf5S\xb5\xdfnl53d\x10\x12\x92\x82\xe1\xe3~\xc8*\x16\x9f\xd69',
        b"{\"data\": \"secret\"}",
        b"authenticated but not encrypted payload"
    )
    response = client.post('/api/publish', query_string=dict(
        ciphertext=str(base64.b64encode(ciphertext), 'utf-8'),
        tag=str(base64.b64encode(tag), 'utf-8'),
        topic="flask_test"
    ), follow_redirects=True)

    assert response.status_code == 200


def test_api_user_register_broker(client, app_and_ctx, access_token_three):
    data = {
        "not-password": "non-empty",
        "access_token": access_token_three
    }
    assert_got_error_from_post(client, '/api/user/broker_register', data, 400, USER_MISSING_PASSWORD_HASH)

    data = {
        "password": "PBKDF2$sha256$10000$+Ezww8vsOcflcODC$OTlWyBkxSHptuqv/glKuu1soqM3W+NNR",  # some_pass
        "access_token": access_token_three
    }
    assert_got_data_from_post(client, '/api/user/broker_register', data, broker_id="3")


def test_api_dt_create(client, app_and_ctx, access_token):
    data = {
        "description": "non-empty",
        "access_token": access_token,
        "correctness_hash": '$2b$12$.Jk4ruyYVQuMcMxpDODfQuV/1NJiLHWDcF15CE9g2OKmCmuSMzU8q'
    }
    status_code, data_out = get_data_from_post(client, '/api/device_type/create', data)
    assert status_code == 200
    assert is_valid_uuid(data_out["type_id"])

    data = {
        "not-description": "non-empty",
        "access_token": access_token,
        "correctness_hash": '$2b$12$EhN.T.Ll2sas/rE34/lkOeyMKzoGZM6SlJoS5xhRUGkkm8T3GAg5O'
    }
    assert_got_error_from_post(client, '/api/device_type/create', data, 400)

    data = {
        "description": "non-empty",
        "access_token": access_token
    }
    assert_got_error_from_post(client, '/api/device_type/create', data, 400)

    app, ctx = app_and_ctx

    with app.app_context():
        inserted_dt = db.session.query(DeviceType).filter(DeviceType.type_id == UUID(data_out["type_id"])).first()
        assert inserted_dt.owner.access_token == "$pbkdf2-sha256$29000$RGVmYXVsdA$sNWluMfh07f0fPLerXr9jInGOAZk8Yo//lY9pOMv61o"
        assert inserted_dt.correctness_hash == '$2b$12$.Jk4ruyYVQuMcMxpDODfQuV/1NJiLHWDcF15CE9g2OKmCmuSMzU8q'


def test_api_dv_create(client, app_and_ctx, access_token, access_token_four):
    data = {
        "not-type_id": "non-empty",
        "access_token": access_token
    }
    assert_got_error_from_post(client, '/api/device/create', data, 400, DEVICE_TYPE_ID_MISSING_ERROR_MSG)

    data = {
        "type_id": "doesnt matter",
        "access_token": access_token
    }
    assert_got_error_from_post(client, '/api/device/create', data, 400, CORRECTNESS_HASH_MISSING_ERROR_MSG)

    data = {
        "type_id": "anything",
        "access_token": access_token,
        "correctness_hash": '$2b$12$EhN.T.Ll2sas/rE34/lkOeyMKzoGZM6SlJoS5xhRUGkkm8T3GAg5O'
    }
    assert_got_error_from_post(client, '/api/device/create', data, 400, DEVICE_NAME_MISSING_ERROR_MSG)

    data = {
        "type_id": "anything",
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": "test"
    }
    assert_got_error_from_post(client, '/api/device/create', data, 400, DEVICE_PASSWORD_MISSING_ERROR_MSG)

    data = {
        "type_id": "anything",
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": "test",
        "password": "PBKDF2$sha256$10000$qu5hXEoBLNeKuzR7$rdth45656456456564"
    }
    assert_got_error_from_post(client, '/api/device/create', data, 400, DEVICE_NAME_BI_MISSING_ERROR_MSG)

    data = {
        "type_id": "non-valid",
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": "test",
        "password": "PBKDF2$sha256$10000$qu5hXEoBLNeKuzR7$rdth45656456456564",
        "name_bi": "$2b$12$1xxxxxxxxxxxxxxxxxxxxuDUX01AKuyu/3/PdSxQT4qMDVTUawIUq"
    }
    assert_got_error_from_post(client, '/api/device/create', data, 400, DEVICE_TYPE_ID_INCORRECT_ERROR_MSG)

    app, ctx = app_and_ctx

    with app.app_context():
        dt = DeviceType(description=b"nothing.....", correctness_hash=correctness_hash("nothing....."))
        db.session.add(dt)
        db.session.commit()
        data = {
            "type_id": str(dt.type_id),
            "access_token": access_token_four,
            "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
            "name": "test",
            "password": "PBKDF2$sha1$10000$qu5hXEoBLNeKuzR7$rdth45656456564",  # invalid
            "name_bi": "$2b$12$1xxxxxxxxxxxxxxxxxxxxuDUX01AKuyu/3/PdSxQT4qMDVTUawIUq"
        }
    assert_got_error_from_post(client, '/api/device/create', data, 400, NOT_REGISTERED_WITH_BROKER_ERROR_MSG)

    data["access_token"] = access_token
    assert_got_error_from_post(client, '/api/device/create', data, 400, INVALID_BROKER_PASSWORD_ERROR_MSG)

    data["password"] = 'PBKDF2$sha256$10000$9tPL2IDSekCbDADg$McfGrlUVABIVQ8mlwBMPtrLH5BemxT5A'
    status, data_out = get_data_from_post(client, '/api/device/create', data)
    assert status == 200
    assert "id" in data_out

    with app.app_context():
        inserted_dv = db.session.query(Device).filter(Device.id == data_out["id"]).first()
        assert inserted_dv.owner.access_token == token_to_hash(data["access_token"])
        assert inserted_dv.name_bi == data["name_bi"]
        assert inserted_dv.users is not None

        assert inserted_dv.mqtt_creds is not None
        assert inserted_dv.mqtt_creds.username == f'd:{data_out["id"]}'
        assert inserted_dv.mqtt_creds.password_hash == data["password"]
        assert len(inserted_dv.mqtt_creds.acls) == 5

        device_owner = User.get_by_access_token(token_to_hash(access_token))
        new_acl = next((acl for acl in device_owner.mqtt_creds.acls if acl.topic == f"u:1/d:{data_out['id']}/"), None)
        assert new_acl is not None, "New ACL for device was not inserted."


def test_api_sc_create(client, app_and_ctx, access_token):
    data = {
        "access_token": access_token,
    }
    assert_got_error_from_post(client, '/api/scene/create', data, 400, SCENE_NAME_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "name": "test_name"
    }
    assert_got_error_from_post(client, '/api/scene/create', data, 400, SCENE_DESC_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "name": "test_name",
        "description": "test_desc"
    }
    assert_got_error_from_post(client, '/api/scene/create', data, 400, SCENE_NAME_BI_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "name": "test_name",
        "description": "test_desc",
        "name_bi": '$2b$12$1xxxxxxxxxxxxxxxxxxxxunmNPfsvRYyz8jVe6tU38FrJIHJJo9C.'
    }
    assert_got_error_from_post(client, '/api/scene/create', data, 400, CORRECTNESS_HASH_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "name": "test_name",
        "description": "test_desc",
        "name_bi": '$2b$12$1xxxxxxxxxxxxxxxxxxxxunmNPfsvRYyz8jVe6tU38FrJIHJJo9C.',
        "correctness_hash": '$2b$12$zElcacWWB.qvf5dEiwkTM.7CNpXchiUXu5y23dajUkGXhSQ1MAH4e'
    }
    assert_got_data_from_post(client, '/api/scene/create', data)

    app, ctx = app_and_ctx

    with app.app_context():
        inserted_sc = db.session.query(Scene).filter(Scene.name_bi == data["name_bi"]).first()
        assert inserted_sc.correctness_hash == '$2b$12$zElcacWWB.qvf5dEiwkTM.7CNpXchiUXu5y23dajUkGXhSQ1MAH4e'


def test_api_add_scene_action(client, app_and_ctx, access_token):
    data = {
        "access_token": access_token,
    }
    assert_got_error_from_post(client, '/api/scene/add_action', data, 400, SCENE_NAME_BI_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "scene_name_bi": "something",
    }
    assert_got_error_from_post(client, '/api/scene/add_action', data, 400, ACTION_NAME_BI_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "scene_name_bi": "something",
        "action_name_bi": "something",
    }
    assert_got_error_from_post(client, '/api/scene/add_action', data, 400, INVALID_SCENE_OR_ACTION_BI_ERROR_MSG)

    data = {
        "access_token": access_token,
        "scene_name_bi": '9c06d92d58a6c3f38fd5dcffef58fedc5502684b1acd4bbede9980803175471a',  # valid
        "action_name_bi": '602b766b0a1d7d5a05df61a2d1b33165e35b57d32d2e5b54a16e21514bdbb9a7',  # unauthorized
    }
    assert_got_error_from_post(client, '/api/scene/add_action', data, 400, UNAUTHORIZED_USER_ERROR_MSG)

    data = {
        "access_token": access_token,
        "scene_name_bi": '9c06d92d58a6c3f38fd5dcffef58fedc5502684b1acd4bbede9980803175471a',  # valid
        "action_name_bi": '86a638eab77f45b9e0e2fb384471e517664df67cec75c33d724efa8649be357e',  # valid
    }
    assert_got_data_from_post(client, '/api/scene/add_action', data)

    data = {
        "access_token": access_token,
        "scene_name_bi": '9c06d92d58a6c3f38fd5dcffef58fedc5502684b1acd4bbede9980803175471a',  # valid
        "action_name_bi": '86a638eab77f45b9e0e2fb384471e517664df67cec75c33d724efa8649be357e',  # already added
    }
    assert_got_error_from_post(client, '/api/scene/add_action', data, 400, ACTION_ALREADY_PRESENT_ERROR_MSG)

    data = {
        "access_token": access_token,
        "scene_name_bi": '0b0a367318926df75879294f1520905ba72d8f1bebe64865645a7e108bfaf3e4',  # other user
        "action_name_bi": '86a638eab77f45b9e0e2fb384471e517664df67cec75c33d724efa8649be357e',
    }
    assert_got_error_from_post(client, '/api/scene/add_action', data, 400, UNAUTHORIZED_USER_SCENE_ERROR_MSG)


def test_api_set_action(client, app_and_ctx, access_token, access_token_four):
    device_id = 23
    data = {
        "device_id": str(device_id),
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
    }
    assert_got_error_from_post(client, '/api/device/set_action', data, 400, ACTION_NAME_MISSING_ERROR_MSG)

    data = {
        "device_id": str(device_id),
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": b'gAAAAABcXV0zhCvu8mmTemaNja01bGK5fIuFjXo-8CpKS96_JTQdD-H-9l_0lwZAyGXp4khjscTC7HMTYL3KL5kuGw6kkJ3XOQ=='.decode("utf-8"),  # cipher.encrypt(b"test_action")
    }
    assert_got_error_from_post(client, '/api/device/set_action', data, 400, ACTION_NAME_BI_MISSING_ERROR_MSG)

    data = {
        "device_id": "9999",  # invalid
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": b'gAAAAABcXV0zhCvu8mmTemaNja01bGK5fIuFjXo-8CpKS96_JTQdD-H-9l_0lwZAyGXp4khjscTC7HMTYL3KL5kuGw6kkJ3XOQ=='.decode("utf-8"),  # cipher.encrypt(b"test_action")
        "name_bi": '$2b$12$1xxxxxxxxxxxxxxxxxxxxudvkMvF2EyHEYeqT1nCqu.XhAt3J3XQ2'  # hash("test_action", str(1))
    }
    assert_got_error_from_post(client, '/api/device/set_action', data, 400, UNAUTHORIZED_USER_ERROR_MSG)

    data["device_id"] = str(device_id)
    data["access_token"] = access_token_four

    assert_got_error_from_post(client, '/api/device/set_action', data, 400, NOT_REGISTERED_WITH_BROKER_ERROR_MSG)

    data["access_token"] = access_token
    assert_got_data_from_post(client, '/api/device/set_action', data)

    app, ctx = app_and_ctx

    with app.app_context():
        ac = db.session.query(Action).filter(Action.name_bi == data["name_bi"]).first()
        assert ac.name.decode("utf-8") == data["name"]
        assert ac.correctness_hash == data["correctness_hash"]

        db.session.delete(ac)
        db.session.commit()


def test_api_get_device_by_name(client, app_and_ctx, access_token):
    data = {"not-name_bi": "non-empty", "access_token": access_token}
    assert_got_error_from_get(client, '/api/device/get', data, 400, DEVICE_NAME_BI_MISSING_ERROR_MSG)

    data = {"name_bi": "non-empty", "access_token": access_token}
    assert_got_data_from_get(client, '/api/device/get', data, devices=[])

    app, ctx = app_and_ctx

    bi_hash = "a36758aa531feb3ef0ce632b7a5rthdfrt2f8df8de854dce915d20df"
    with app.app_context():
        dt = DeviceType(id=123, description=b"nothing...", correctness_hash=correctness_hash("nothing..."))
        db.session.add(dt)
        dv = Device(id=1000,
                    status=b"0",
                    device_type=dt,
                    name=b"my_raspberry",
                    name_bi=bi_hash,
                    correctness_hash=correctness_hash("my_raspberry"),
                    owner_id=1)
        db.session.add(dv)
        db.session.commit()
        data = {"name_bi": bi_hash, "access_token": access_token}

    status, data_out = get_data_from_get(client, '/api/device/get', data)
    assert status == 200
    devices = list(filter(lambda d: d["id"] == 1000, data_out["devices"]))
    assert len(devices) == 1


def test_api_get_device_by_name_foreign_device_hash(client, app_and_ctx, access_token):
    data = {
        "name_bi": "19f0eb580950646713d77c0f4e053083fedeb27865191163a72b0c49d3210969",
        "access_token": access_token
    }
    assert_got_data_from_get(client, '/api/device/get', data, devices=[])


def test_api_get_device_data_by_range_missing_device_id(client, app_and_ctx, access_token):
    data = {"not-upper-or-lower": "non-empty", "access_token": access_token}
    assert_got_error_from_get(client, '/api/data/get_by_num_range', data, 400, DEVICE_NAME_BI_MISSING_ERROR_MSG)


def test_api_get_device_data_by_range_missing_bounds(client, app_and_ctx, access_token):
    data = {"not-upper-or-lower": "non-empty", "access_token": access_token, "device_name_bi": "a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df"}
    assert_got_error_from_get(client, '/api/data/get_by_num_range', data, 400, DATA_RANGE_MISSING_ERROR_MSG)


def test_api_get_device_data_by_range_non_numeric_bound(client, app_and_ctx, access_token):
    data = {"lower": "non-numeric", "access_token": access_token, "device_name_bi": "a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df"}
    assert_got_error_from_get(client, '/api/data/get_by_num_range', data, 400, DATA_RANGE_MISSING_ERROR_MSG)


def test_api_get_device_data_by_range_with_only_lower_bound(client, app_and_ctx, access_token):
    data = {"lower": "467297", "access_token": access_token, "device_name_bi": "a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df"}  # 2500
    status_code, data_out = get_data_from_get(client, '/api/data/get_by_num_range', data)

    assert status_code == 200
    assert len(data_out["device_data"]) == 2


def test_api_get_device_data_by_range_with_only_upper_bound(client, app_and_ctx, access_token):
    data = {"upper": "469439", "access_token": access_token, "device_name_bi": "a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df"}  # 3500
    status_code, data_out = get_data_from_get(client, '/api/data/get_by_num_range', data)

    assert status_code == 200
    assert len(data_out["device_data"]) == 3


def test_api_get_device_data_by_range_with_both_bounds(client, app_and_ctx, access_token):
    data = {
        "lower": "465606",  # 1700
        "upper": "470477",  # 4000
        "access_token": access_token,
        "device_name_bi": "a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df"
    }
    status_code, data_out = get_data_from_get(client, '/api/data/get_by_num_range', data)

    assert status_code == 200
    assert len(data_out["device_data"]) == 2

    data = {
        "lower": "472693",  # 5000
        "upper": "487525",  # 12000
        "access_token": access_token,
        "device_name_bi": "a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df"
    }
    status_code, data_out = get_data_from_get(client, '/api/data/get_by_num_range', data)

    assert status_code == 200
    assert len(data_out["device_data"]) == 0


def test_api_get_device_data_by_range_out_of_range(client, app_and_ctx, access_token):
    device_name_bi = "a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df"
    cipher_range = instantiate_ope_cipher(b"").out_range
    data = {"upper": str(cipher_range.end + 1), "access_token": access_token, "device_name_bi": device_name_bi}
    assert_got_error_from_get(client, '/api/data/get_by_num_range', data, 400, DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG)

    data = {"lower": str(cipher_range.start - 1), "access_token": access_token, "device_name_bi": device_name_bi}  # -1
    assert_got_error_from_get(client, '/api/data/get_by_num_range', data, 400, DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG)

    data = {"lower": "1", "upper": str(cipher_range.end + 1), "access_token": access_token, "device_name_bi": device_name_bi}  # lower OK, upper not OK
    assert_got_error_from_get(client, '/api/data/get_by_num_range', data, 400, DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG)


def test_api_get_device_data(client, app_and_ctx, access_token_two):
    data = {"not-device_name_bi": "non-empty", "access_token": access_token_two}
    assert_got_error_from_get(client, '/api/data/get_device_data', data, 400, DEVICE_NAME_BI_MISSING_ERROR_MSG)

    data = {"device_name_bi": "invalid", "access_token": access_token_two}
    assert_got_error_from_get(client, '/api/data/get_device_data', data, 400, DEVICE_NAME_BI_INVALID_ERROR_MSG)

    device_name_bi = "6c0d409f3d4d630303ca1fea9d1d0b2aa9aef33e0480266e23eb24c6b26a3fde"
    data = {"device_name_bi": device_name_bi, "access_token": access_token_two}
    status_code, data_out = get_data_from_get(client, '/api/data/get_device_data', data)

    assert status_code == 200
    assert len(data_out["device_data"]) == 2


def test_api_trigger_action(client, app_and_ctx, access_token):
    device_id = "23"
    data = {
        "device_id": device_id,
        "name_bi": '$2b$12$1xxxxxxxxxxxxxxxxxxxxuz5Jia.EInvalid6Nte',
        "access_token": access_token
    }
    assert_got_error_from_get(client, '/api/device/action', data, 400, ACTION_BI_INVALID_ERROR_MSG)

    data = {
        "device_id": device_id,
        "name_bi": '86a638eab77f45b9e0e2fb384471e517664df67cec75c33d724efa8649be357e',
        "access_token": access_token
    }

    app, ctx = app_and_ctx
    with app.app_context():
        ac_name_string = Action.get_by_id(2).name.decode("utf-8")
        with mock.patch('app.app_setup.client.publish') as publish:
            assert_got_data_from_get(client, '/api/device/action', data)

            publish.assert_called_once()
            args = publish.call_args
            assert args == ((f"u:1/d:23/", f'"{{"\\"action\\"": "\\"{ac_name_string}\\"", "\\"user_id\\"": "\\"u:1\\""}}"'),)


def test_api_trigger_scene(client, app_and_ctx, access_token, access_token_two):
    data = {
        "access_token": access_token,
        "name_bi": "something"
    }
    assert_got_error_from_get(client, '/api/scene/trigger', data, 400, INVALID_SCENE_BI_ERROR_MSG)

    data = {
        "access_token": access_token,
        "name_bi": '0b0a367318926df75879294f1520905ba72d8f1bebe64865645a7e108bfaf3e4',  # other user
    }
    assert_got_error_from_get(client, '/api/scene/trigger', data, 400, UNAUTHORIZED_USER_SCENE_ERROR_MSG)

    data = {
        "access_token": access_token_two,
        "name_bi": '0b0a367318926df75879294f1520905ba72d8f1bebe64865645a7e108bfaf3e4',
    }

    app, ctx = app_and_ctx
    with app.app_context():
        with mock.patch('app.app_setup.client.publish') as publish:
            assert_got_data_from_get(client, '/api/scene/trigger', data)

            expected_calls = [
                call('u:2/d:45/', '"{"\\"action\\"": "\\"gAAAAABcYAJr_P_8E4S0nWTFU-uyGk8t3MDexB5LzNGHKB6rd_pwKwY41bTMYYqAvuxcrCp3BBYwh7FI4F6fkswMM5JAFMcmqQ==\\"", "\\"user_id\\"": "\\"u:2\\""}"'),
                call('u:2/d:34/', '"{"\\"action\\"": "\\"gAAAAABcYAJs8wCzyfEdHGO3TUjK-EeSxD-wFEgCGY8XF_kExmttrzUjM-YFKUaySrc8yLJG8UXe2zLtGr7LPAl5xyW756XscA==\\"", "\\"user_id\\"": "\\"u:2\\""}"'),
                call('u:2/d:37/', '"{"\\"action\\"": "\\"gAAAAABcYAJsJHci8zzKE232PYIX-Hw74lYNEt_f7EceuroDqp0pWHGD96_baLE2tlQeFlFRenmpmFwtBZQbLIyBfAPaBXnl-A==\\"", "\\"user_id\\"": "\\"u:2\\""}"')
            ]

            assert all(v in expected_calls for v in publish.mock_calls)
            assert publish.call_count == 3


def test_api_authorize_user(client, app_and_ctx, access_token, access_token_two):
    data = {
        "access_token": access_token,
    }
    assert_got_error_from_post(client, '/api/device/authorize', data, 400, DEVICE_ID_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": "something",
    }
    assert_got_error_from_post(client, '/api/device/authorize', data, 400, AUTH_USER_ID_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": "something",
        "auth_user_id": "invalid",
    }
    assert_got_error_from_post(client, '/api/device/authorize', data, 400, AUTH_USER_ID_INVALID_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": "something",
        "auth_user_id": 1,  # Can't authorize self
    }
    assert_got_error_from_post(client, '/api/device/authorize', data, 400, AUTH_USER_ID_INVALID_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": 45,  # Belongs to other user
        "auth_user_id": 2,
    }
    assert_got_error_from_post(client, '/api/device/authorize', data, 400, UNAUTHORIZED_USER_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": 23,
        "auth_user_id": 4,  # Not registered with MQTT broker
    }
    assert_got_error_from_post(client, '/api/device/authorize', data, 400, NOT_REGISTERED_WITH_BROKER_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": 23,
        "auth_user_id": 2,
    }
    assert_got_data_from_post(client, '/api/device/authorize', data)

    app, ctx = app_and_ctx
    with app.app_context():
        auth_user = User.get_by_access_token(token_to_hash(access_token_two))
        auth_device = Device.get_by_id(23)

        assert next((ud for ud in auth_device.users if ud.user_id == auth_user.id), None) is not None
        assert next((ud for ud in auth_user.devices if ud.device_id == auth_device.id), None) is not None

        new_creds_user = [acl for acl in auth_user.mqtt_creds.acls if f"d:23" in acl.topic]
        new_creds_device = [acl for acl in auth_device.mqtt_creds.acls if f"u:2" in acl.topic]
        assert len(new_creds_user) == 3
        assert len(new_creds_device) == 2

    data = {
        "access_token": access_token,
        "device_id": 23,
        "auth_user_id": 2,  # already authorized
    }
    assert_got_error_from_post(client, '/api/device/authorize', data, 400, AUTH_USER_ALREADY_AUTHORIZED_ERROR_MSG)


def test_api_revoke_user(client, app_and_ctx, access_token, access_token_two):
    data = {
        "access_token": access_token,
    }
    assert_got_error_from_post(client, '/api/device/revoke', data, 400, DEVICE_ID_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": "something",
    }
    assert_got_error_from_post(client, '/api/device/revoke', data, 400, REVOKE_USER_ID_MISSING_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": "something",
        "revoke_user_id": "invalid",
    }
    assert_got_error_from_post(client, '/api/device/revoke', data, 400, REVOKE_USER_ID_INVALID_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": "something",
        "revoke_user_id": 1,  # Can't revoke self
    }
    assert_got_error_from_post(client, '/api/device/revoke', data, 400, REVOKE_USER_ID_INVALID_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": 45,  # Belongs to other user
        "revoke_user_id": 2,
    }
    assert_got_error_from_post(client, '/api/device/revoke', data, 400, UNAUTHORIZED_USER_ERROR_MSG)

    data = {
        "access_token": access_token,
        "device_id": 23,
        "revoke_user_id": 2,
    }
    assert_got_data_from_post(client, '/api/device/revoke', data)

    app, ctx = app_and_ctx
    with app.app_context():
        auth_user = User.get_by_access_token(token_to_hash(access_token_two))
        auth_device = Device.get_by_id(23)
        assert UserDevice.get_by_ids(23, 2) is None
        removed_creds_user = [acl for acl in auth_user.mqtt_creds.acls if f"d:23" in acl.topic]
        removed_creds_device = [acl for acl in auth_device.mqtt_creds.acls if f"u:2" in acl.topic]
        assert len(removed_creds_user) == 0
        assert len(removed_creds_device) == 0

    data = {
        "access_token": access_token_two,
        "device_id": 45,
        "revoke_user_id": 1,  # not authorized
    }
    assert_got_error_from_post(client, '/api/device/revoke', data, 400, REVOKE_USER_NOT_AUTHORIZED_ERROR_MSG)


def test_correctness_hash():
    assert bcrypt.verify("ergh" + "esrge", correctness_hash("ergh", "esrge"))
    assert not bcrypt.verify("ergh" + "esrge" + "wes", correctness_hash("ergh", "esrge"))


def test_wave_func():
    funcs = [triangle_wave, sawtooth_wave, square_wave, sine_wave]
    for f in funcs:
        gen = f()
        assert isinstance(gen, types.GeneratorType)
        assert len(list(gen)) == 500


def test_generate_fake_tuple_and_hash():
    columns = {
            "added": {
                "seed": 345453,
                "lower_bound": 0,
                "upper_bound": 0,
                "type": "OPE"
            },
            "num_data": {
                "seed": 345236,
                "lower_bound": 0,
                "upper_bound": 0,
                "type": "OPE"
            },
            "data": {
                "seed": -2345625462,
                "lower_bound": 0,
                "upper_bound": 0,
                "type": "ABE"
            },
            "tid": {
                "lower_bound": 1,
                "upper_bound": 1,
                "type": "Fernet"
            }
        }

    d = generate(columns)
    assert d["added"] == -168754978
    assert d["num_data"] == 83924723
    assert d["data"] == 2070235132
    assert d["tid"] == 1


def test_encrypt_fake_tuple():
    fake_tuple = {
        "tid": 1,
        "added": -1000,
        "num_data": -1000,
        "data": 1000,
    }

    keys = {
        "added": ["217b5c3430fd77e7a0191f04cbaf872be189d8cb203c54f7b083211e8e5f4f70", "OPE"],
        "num_data": ["a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d", "OPE"],
        "data": [
            "eJyVVstuGzEM/BXDZx9E7erVXykCwy1S55BDgbQFiiD/Xg05Izs9JQd711yJOzMcUn49Xo9fDq/H8/n78+Xl5Xyev47f/v56fDmeDjP65/L8+9GjX/dxOpR+OtR2OvT5afNTbF7LvKbTYZ/PCmJbxM3q/Mrzrs4VtTLS9ti+NwTm2jrzIrcZojPQ8+1qKccWX55TLG0z2DufWvK7wk0WGas9vE0G1/xReqAAek5NYC3xV98i/XDUO1kCRgIugEx88QTSwXHEIksjtkEvPLCEfDVWW5qRNmI78oFaaNVC0tpJvIkrKHZfogTAvvQoheCRBvCAHagg4RiE67BWDRCG3AAMASwZl3gBfR0U7qj1rrKAekpkloVlC+6wySBlXyAenghkysQ3SAyJoTOSo9zAC1m6k0lClBcsvNcXbUF0F9YiIK6z1yq2RRYt8zLhassrT5/thC6X+8sD1ha1aV3uLkEIYnnRIL5Xooc2UQOsMvWNMSKMnlAidVbAcijmbWfLDa5X5/ve98KPz/KDtk6i0Br4IHE0Y6a8Ts/CRHCiW7epe7xSfWmzCWQ4bFM70RNNnig3dfDbTWmN5EJrKP8fxcfz9Xq+PP98uny47S24EtTO8SOzRvdl6uBfoNpX52ksFU6ywobzIGq880FtmldOAwzQnAh7/xvvdw0Gi+zeQ6vbXdpOf2EYVM6O5SskKFVj0TRO0Az7RmMVmpJFyGsmpADlBsscw9FMeHFlcSLh0DgSp6bpnjXo1sS73+Tnx1B/IoNDvvVpDedpKuIaji/qNGG9ez/VHhpe+80renFXS5Glr2tqNk9RqsSud10J6BhhMINvjKdZFJvUHHcah2EyzV/UIxwb3jM55IxDhnX3ocdzrDRN4xIP8fKm6b+C9R5CpnBCUHk6u6LqNnppnRr1dqy6hSh0YSG9G8DZzzOMJ9wMuY7e4fFQdcI0TVllzWwXNL0OQz+svDh9je32bpglzW7/b1FvR0eTSuuvwhb6xim4Pby9/QMmWbTA",
            "ABE",
            "1-23 1-GUEST 1"],
        "tid": ["d011b0fa5a23b3c2efadb2e0fea094647ff7b03b9a93022aeae6c1edf3eb1871", "Fernet"]
    }

    result = encrypt_row(fake_tuple, keys)
    plaintext = decrypt_using_abe_serialized_key(result["data"], keys["data"][0], "eJydVstuFDEQ/JXVnhfJ9vjJOYgPCJxQtAooF5QDYgMSivLvuLqrvCPBJTmsdsZj96OqutvPx5vj+8Pz8Xz+9nh/uZzP8+349c/Tw+V4OszV3/ePvx5s9UsJp0Ppp0Mf8z+fDjFu86GdDi3xpc+vdS7EsGEFyyHiaeBpfixzvc2XPJ+bfYGd0Hyl1rkjYGGe7GX+zNbcX+fXAffJz8eIrfM3+KFrw1xr8z/jZIw8XqatjPiCHCBqeB2MsyiOVpWChVd8HyKzYCzeGJhi0/HRHJaYoscUQ/aTcGkHEFFH+NkjJDzJoyv2Ai+Vq+47+meYRGqGdmdqWLCMMilIK5HhPiqP9E3ZiQ1L0fgrZGM4iPSNLSBg7q/2u3uZcrj5blqJr1VMRTybRxxDYMrSiAUV4G3GPgZTt+gMkqUzfC9C2uDZnBZgunhdAsydhK0Hwx0UOUqVfmEG2bbiOJRIMdE84IMCQV8n2/hWK5kYxie8pCC5wx/yNuwlVxMM/JbCo50/hyaK2uwRGbWFBioNIAsLq7r11pbPss84dEUF/TVKHmbtk+8pV1U6rJunY4rL/ltlyHLNXiaOOIvOxAfb9rtKJr5L22vlYh5WNcBVX+XZnB7g11j/5tqL0kQhwcWFqIBjFRkEDtjwvbbP5R9dD62KuixOomxWdbO4E6/JGYF39bXBIIxABI9gu6Rt/aBwAeD6w8YY1MgGmUKBGyfqJ4VoeG2Pa97WQZCyGYTazRUF4wvbrhYsCAPj2rkbmTVI8DYkXFN4G1JwUOJFEt4cF1d5cl8OcaJDa+bde9d/FfPx84fbT68VjSkje/mDgqGZw46W3SGwKOrYmfkM5eu8sVoAmdGwCdRFscx2lkJT1+6JlqwoAyvLdFnlxHtv3Qs4OgWNrHXNHutKSfiyVXhlRNVJZDtZFHlb6uxTwQFnkWQlauwmV40V/8YQOMYNTg4mH/ZSQRKKxUUIiPC+umJzyS/5FSJmLbSyrSZPIavmOgXBDkpbQ2T2f+eRD6Qfr5tIGPjeYoKQ7X4NKORgsC7XNUOdsBPRuu4B3mCTG2q6bKwJ1tRhvFS6FBT77uJhvaZrIrEvZFUiCucNjVRZds1ydZK6bhdpP3ivQ7+zReWuScEiRZyZlqy+U1Sh6/ZXpY6qfNJuslSNx6HKKJSx1/9bal95Nt1mkFFnKD5rKUYTJGt5sHuuorIi15wDOyZ6dgDrkzYVpMUmavO+0+TrFc+EsS4pTmS5ivYWoR8vTz/fR2RkDyB3PTsGdy9/AbtMQWU=")
    assert plaintext == '1000'

    plaintext = decrypt_using_ope_hex(keys["num_data"][0], result["num_data"])
    assert plaintext == -1000

    result = encrypt_row(fake_tuple, keys)
    plaintext = decrypt_using_fernet_hex(keys["tid"][0], result["tid"])
    assert plaintext.decode() == '1'


def test_bytes_to_json():
    val = b'"{\'user_public_key\': \'-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7duCMX2lDbj0KiC3fODqQp3oDXHoVvUa\nVOgbxNMo73cjgiJFtHo9T2UZZxu/bAEZ81ZF4pHryv1TK5VUcqprKTlPYDSj1n6A\nzYQVz/mV5Ou4eZOOBhoovV5YwJUJo2yW\n-----END PUBLIC KEY-----\n\', \'user_id\': \'1\'}"'

    result = bytes_to_json(val)
    assert isinstance(result, dict)


def test_format_topic():
    assert format_topic("u:1", "d:4") == f"u:1/d:4/"
    assert format_topic("d:5", "u:23") == f"d:5/u:23/"


def test_validate_broker_password():
    invalid = 'PBKD2$sha256$10000$m0FVLYZC1DcwZQFy$MPYAEv8i7rTIsPfgbeV9eJch/h03tK41'
    assert not validate_broker_password(invalid)

    invalid = 'PBKDF2$sha1$10000$m0FVLYZC1DcwZQFy$MPYAEv8i7rTIsPfgbeV9eJch/h03tK41'
    assert not validate_broker_password(invalid)

    invalid = 'PBKDF2$sha256$1k000$m0FVLYZC1DcwZQFy$MPYAEv8i7rTIsPfgbeV9eJch/h03tK41'
    assert not validate_broker_password(invalid)

    invalid = 'PBKDF2$sha256$10000$m0FVLYZC1DcwZQF$MPYAEv8i7rTIsPfgbeV9eJch/h03tK41'
    assert not validate_broker_password(invalid)

    invalid = 'PBKDF2$sha256$10000$m0FVLYZC1DcwZQFy$MPYAEv8i7rTIsPfgbeV9eJch/h03tK4'
    assert not validate_broker_password(invalid)

    valid = 'PBKDF2$sha256$10000$m0FVLYZC1DcwZQFy$MPYAEv8i7rTIsPfgbeV9eJch/h03tK41'
    assert validate_broker_password(valid)
