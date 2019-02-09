# -*- coding: utf-8 -*-
import base64
import json
import types
from unittest import mock
from uuid import UUID

import pytest
from passlib.hash import bcrypt

from app.consts import DEVICE_TYPE_ID_MISSING_ERROR_MSG, DEVICE_TYPE_ID_INCORRECT_ERROR_MSG, \
    DEVICE_NAME_BI_MISSING_ERROR_MSG, DEVICE_NAME_MISSING_ERROR_MSG, \
    DATA_RANGE_MISSING_ERROR_MSG, DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG, CORRECTNESS_HASH_MISSING_ERROR_MSG, \
    SOMETHING_WENT_WRONG_MSG, DEVICE_ID_MISSING_ERROR_MSG, \
    DEVICE_NAME_INVALID_ERROR_MSG, DEVICE_PASSWORD_MISSING_ERROR_MSG, USER_MISSING_PASSWORD_HASH, ACTION_NAME_MISSING_ERROR_MSG, \
    ACTION_NAME_BI_MISSING_ERROR_MSG, UNAUTHORIZED_USER_ERROR_MSG, ACTION_BI_INVALID_ERROR_MSG
from app.models.models import DeviceType, Device, User, Action
from app.app_setup import client as mqtt_client
from app.utils import is_valid_uuid, bytes_to_json, format_topic
from client.crypto_utils import encrypt, hash, correctness_hash, triangle_wave, sawtooth_wave, square_wave, sine_wave, generate, fake_tuple_to_hash, \
    encrypt_fake_tuple, instantiate_ope_cipher, decrypt_using_fernet_hex, decrypt_using_ope_hex

from .conftest import db


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


def test_api_user_register_broker(client, app_and_ctx, access_token_tree):
    data = {
        "not-password": "non-empty",
        "access_token": access_token_tree
    }
    response = client.post('/api/user/broker_register', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == USER_MISSING_PASSWORD_HASH

    data = {
        "password": "PBKDF2$sha256$10000$+Ezww8vsOcflcODC$OTlWyBkxSHptuqv/glKuu1soqM3W+NNR",  # some_pass
        "access_token": access_token_tree
    }
    response = client.post('/api/user/broker_register', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["broker_id"]) == "3"


def test_api_dt_create(client, app_and_ctx, access_token):
    data = {
        "description": "non-empty",
        "access_token": access_token,
        "correctness_hash": '$2b$12$.Jk4ruyYVQuMcMxpDODfQuV/1NJiLHWDcF15CE9g2OKmCmuSMzU8q'
    }
    response = client.post('/api/device_type/create', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert is_valid_uuid(json_data["type_id"])

    data = {
        "not-description": "non-empty",
        "access_token": access_token,
        "correctness_hash": '$2b$12$EhN.T.Ll2sas/rE34/lkOeyMKzoGZM6SlJoS5xhRUGkkm8T3GAg5O'
    }
    response = client.post('/api/device_type/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400

    data = {
        "description": "non-empty",
        "access_token": access_token
    }
    response = client.post('/api/device_type/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400

    app, ctx = app_and_ctx

    with app.app_context():
        inserted_dt = db.session.query(DeviceType).filter(DeviceType.type_id == UUID(json_data["type_id"])).first()
        assert inserted_dt.owner.access_token == "5c36ab84439c45a3719644c0d9bd7b31929afd9f"
        assert inserted_dt.correctness_hash == '$2b$12$.Jk4ruyYVQuMcMxpDODfQuV/1NJiLHWDcF15CE9g2OKmCmuSMzU8q'


def test_api_dv_create(client, app_and_ctx, access_token):
    data = {
        "not-type_id": "non-empty",
        "access_token": access_token
    }
    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_TYPE_ID_MISSING_ERROR_MSG

    data = {
        "type_id": "doesnt matter",
        "access_token": access_token
    }
    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == CORRECTNESS_HASH_MISSING_ERROR_MSG

    data = {
        "type_id": "anything",
        "access_token": access_token,
        "correctness_hash": '$2b$12$EhN.T.Ll2sas/rE34/lkOeyMKzoGZM6SlJoS5xhRUGkkm8T3GAg5O'
    }
    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_NAME_MISSING_ERROR_MSG

    data = {
        "type_id": "anything",
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": "test"
    }
    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_PASSWORD_MISSING_ERROR_MSG

    data = {
        "type_id": "anything",
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": "test",
        "password": "PBKDF2$sha256$10000$qu5hXEoBLNeKuzR7$rdth45656456456564"
    }
    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_NAME_BI_MISSING_ERROR_MSG

    data = {
        "type_id": "non-valid",
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": "test",
        "password": "PBKDF2$sha256$10000$qu5hXEoBLNeKuzR7$rdth45656456456564",
        "name_bi": "$2b$12$1xxxxxxxxxxxxxxxxxxxxuDUX01AKuyu/3/PdSxQT4qMDVTUawIUq"
    }
    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_TYPE_ID_INCORRECT_ERROR_MSG

    app, ctx = app_and_ctx

    with app.app_context():
        dt = DeviceType(description=b"nothing.....", correctness_hash=correctness_hash("nothing....."))
        db.session.add(dt)
        db.session.commit()
        data = {
            "type_id": str(dt.type_id),
            "access_token": access_token,
            "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
            "name": "test",
            "password": "PBKDF2$sha256$10000$qu5hXEoBLNeKuzR7$rdth45656456456564",
            "name_bi": "$2b$12$1xxxxxxxxxxxxxxxxxxxxuDUX01AKuyu/3/PdSxQT4qMDVTUawIUq"
        }

    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert "id" in json_data

    with app.app_context():
        inserted_dv = db.session.query(Device).filter(Device.id == json_data["id"]).first()
        assert inserted_dv.owner.access_token == data["access_token"]
        assert inserted_dv.name_bi == data["name_bi"]
        assert inserted_dv.users is not None

        assert inserted_dv.mqtt_creds is not None
        assert inserted_dv.mqtt_creds.username == str(json_data["id"])
        assert inserted_dv.mqtt_creds.password_hash == data["password"]
        assert len(inserted_dv.mqtt_creds.acls) == 5

        device_owner = User.get_by_access_token(access_token)
        new_acl = next((acl for acl in device_owner.mqtt_creds.acls if acl.topic == f"u:1/d:{json_data['id']}/"), None)
        assert new_acl is not None, "New ACL for device was not inserted."


def test_api_set_action(client, app_and_ctx, access_token):
    device_id = 23
    data = {
        "device_id": str(device_id),
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
    }
    response = client.post('/api/device/set_action', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == ACTION_NAME_MISSING_ERROR_MSG

    data = {
        "device_id": str(device_id),
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": b'gAAAAABcXV0zhCvu8mmTemaNja01bGK5fIuFjXo-8CpKS96_JTQdD-H-9l_0lwZAyGXp4khjscTC7HMTYL3KL5kuGw6kkJ3XOQ=='.decode("utf-8"),  # cipher.encrypt(b"test_action")
    }
    response = client.post('/api/device/set_action', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == ACTION_NAME_BI_MISSING_ERROR_MSG

    data = {
        "device_id": "9999",  # invalid
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": b'gAAAAABcXV0zhCvu8mmTemaNja01bGK5fIuFjXo-8CpKS96_JTQdD-H-9l_0lwZAyGXp4khjscTC7HMTYL3KL5kuGw6kkJ3XOQ=='.decode("utf-8"),  # cipher.encrypt(b"test_action")
        "name_bi": '$2b$12$1xxxxxxxxxxxxxxxxxxxxudvkMvF2EyHEYeqT1nCqu.XhAt3J3XQ2'  # hash("test_action", str(1))
    }
    response = client.post('/api/device/set_action', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == UNAUTHORIZED_USER_ERROR_MSG

    data["device_id"] = str(device_id)
    response = client.post('/api/device/set_action', query_string=data, follow_redirects=True)
    assert response.status_code == 200

    app, ctx = app_and_ctx

    with app.app_context():
        ac = db.session.query(Action).filter(Action.name_bi == data["name_bi"]).first()
        assert ac.name.decode("utf-8") == data["name"]
        assert ac.correctness_hash == data["correctness_hash"]

        db.session.delete(ac)
        db.session.commit()


def test_api_get_device_by_name(client, app_and_ctx, access_token):
    data = {"not-name_bi": "non-empty", "access_token": access_token}
    response = client.post('/api/device/get', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_NAME_BI_MISSING_ERROR_MSG

    data = {"name_bi": "non-empty", "access_token": access_token}
    response = client.post('/api/device/get', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["devices"] == []

    app, ctx = app_and_ctx

    bi_hash = "$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq"
    with app.app_context():
        dt = DeviceType(id=123, description=b"nothing...", correctness_hash=correctness_hash("nothing..."))
        db.session.add(dt)
        dv = Device(id=1000,
                    status=b"0",
                    device_type=dt,
                    name=b"my_raspberry",
                    name_bi=bi_hash,
                    correctness_hash=correctness_hash("my_raspberry"))
        db.session.add(dv)
        db.session.commit()
        data = {"name_bi": bi_hash, "access_token": access_token}

    response = client.post('/api/device/get', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    devices = list(filter(lambda d: d["id"] == 23, json_data["devices"]))
    assert len(devices) == 1


def test_api_get_device_by_name_foreign_device_hash(client, app_and_ctx, access_token):
    data = {
        "name_bi": "$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm",
        "access_token": access_token
    }

    response = client.post('/api/device/get', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["devices"]) == 0


def test_api_get_device_data_by_range_missing_device_id(client, app_and_ctx, access_token):
    data = {"not-upper-or-lower": "non-empty", "access_token": access_token}
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_ID_MISSING_ERROR_MSG


def test_api_get_device_data_by_range_missing_bounds(client, app_and_ctx, access_token):
    data = {"not-upper-or-lower": "non-empty", "access_token": access_token, "device_id": 23}
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DATA_RANGE_MISSING_ERROR_MSG


def test_api_get_device_data_by_range_non_numeric_bound(client, app_and_ctx, access_token):
    data = {"lower": "non-numeric", "access_token": access_token, "device_id": 23}
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DATA_RANGE_MISSING_ERROR_MSG


def test_api_get_device_data_by_range_with_only_lower_bound(client, app_and_ctx, access_token):
    data = {"lower": "467297", "access_token": access_token, "device_id": 23}  # 2500
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 2


def test_api_get_device_data_by_range_with_only_upper_bound(client, app_and_ctx, access_token):
    data = {"upper": "469439", "access_token": access_token, "device_id": 23}  # 3500
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 3


def test_api_get_device_data_by_range_with_both_bounds(client, app_and_ctx, access_token):
    data = {
        "lower": "465606",  # 1700
        "upper": "470477",  # 4000
        "access_token": access_token,
        "device_id": 23
        }
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 2

    data = {
        "lower": "472693",  # 5000
        "upper": "487525",  # 12000
        "access_token": access_token,
        "device_id": 23
    }
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 0


def test_api_get_device_data_by_range_out_of_range(client, app_and_ctx, access_token):
    cipher_range = instantiate_ope_cipher(b"").out_range
    data = {"upper": str(cipher_range.end + 1), "access_token": access_token, "device_id": 23}
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG
    data = {"lower": str(cipher_range.start - 1), "access_token": access_token, "device_id": 23}  # -1
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG
    data = {"lower": "1", "upper": str(cipher_range.end + 1), "access_token": access_token, "device_id": 23}  # lower OK, upper not OK
    response = client.post('/api/data/get_by_num_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG


def test_api_get_device_data(client, app_and_ctx, access_token_two):
    data = {"not-device_id": "non-empty", "access_token": access_token_two}
    response = client.post('/api/data/get_device_data', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DEVICE_ID_MISSING_ERROR_MSG

    data = {"device_id": "not-a-number", "access_token": access_token_two}
    response = client.post('/api/data/get_device_data', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DEVICE_NAME_INVALID_ERROR_MSG

    device_id = 45
    data = {"device_id": str(device_id), "access_token": access_token_two}
    response = client.post('/api/data/get_device_data', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 2


def test_api_trigger_action(client, app_and_ctx, access_token):
    device_id = "23"
    data = {
        "device_id": device_id,
        "name_bi": '$2b$12$1xxxxxxxxxxxxxxxxxxxxuz5Jia.EInvalid6Nte',
        "access_token": access_token
    }
    response = client.post('/api/device/action', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == ACTION_BI_INVALID_ERROR_MSG

    data = {
        "device_id": device_id,
        "name_bi": '$2b$12$1xxxxxxxxxxxxxxxxxxxxuz5Jia.EDkTwFaphV2YY8UhBMcuo6Nte',
        "access_token": access_token
    }

    app, ctx = app_and_ctx
    with app.app_context():
        ac_name_string = Action.get_by_id(2).name.decode("utf-8")
        with mock.patch('app.app_setup.client.publish') as publish:
            response = client.post('/api/device/action', query_string=data, follow_redirects=True)
            assert response.status_code == 200

            publish.assert_called_once()
            args = publish.call_args
            assert args == ((f"u:1/d:23/", f'"{{"\\"action\\"": "\\"{ac_name_string}\\"", "\\"user_id\\"": "\\"1\\""}}"'),)


def test_hash_bcrypt():
    assert hash("raspberry", "1234srfh") == "$2b$12$1234srfhxxxxxxxxxxxxxu9oRez2BjitmNvretimcFcTsuR/HtxQa"
    with pytest.raises(Exception):
        hash("raspberry", "")


def test_correctness_hash():
    assert bcrypt.verify("ergh" + "esrge", correctness_hash("ergh", "esrge"))
    assert bcrypt.verify("ergh" + "esrge" + "1", correctness_hash("ergh", "esrge", fake=True))
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
                "function_name": "triangle_wave",
                "lower_bound": 0,
                "upper_bound": 0,
                "is_numeric": True
            },
            "num_data": {
                "function_name": "sawtooth_wave",
                "lower_bound": 0,
                "upper_bound": 0,
                "is_numeric": True
            },
            "data": {
                "function_name": "square_wave",
                "lower_bound": 0,
                "upper_bound": 0,
                "is_numeric": False
            },
            "tid": {
                "function_name": "index_function",
                "lower_bound": 0,
                "upper_bound": 0,
                "is_numeric": False
            }
        }

    d = generate(columns)
    assert d["added"] == -1000
    assert d["num_data"] == -1000
    assert d["data"] == 1000
    assert d["tid"] == 1

    fake_tuple_hash = fake_tuple_to_hash(d.values())
    assert bcrypt.verify("-1000" + "-1000" + "1000" + "1" + "1", fake_tuple_hash)


def test_encrypt_fake_tuple():
    fake_tuple = {
        "tid": 1,
        "added": -1000,
        "num_data": -1000,
        "data": 1000,
    }

    keys = {
        "added": ["217b5c3430fd77e7a0191f04cbaf872be189d8cb203c54f7b083211e8e5f4f70", True],
        "num_data": ["a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d", True],
        "data": ["d011b0fa5a23b3c2efadb2e0fea094647ff7b03b9a93022aeae6c1edf3eb1871", False],
        "tid": ["d011b0fa5a23b3c2efadb2e0fea094647ff7b03b9a93022aeae6c1edf3eb1871", False]
    }

    result = encrypt_fake_tuple(fake_tuple, keys)
    plaintext = decrypt_using_fernet_hex(keys["data"][0], result["data"])
    assert plaintext.decode() == '1000'

    plaintext = decrypt_using_ope_hex(keys["num_data"][0], result["num_data"])
    assert plaintext == -1000

    result = encrypt_fake_tuple(fake_tuple, keys)
    plaintext = decrypt_using_fernet_hex(keys["tid"][0], result["tid"])
    assert plaintext.decode() == '1'


def test_bytes_to_json():
    val = b'"{\'user_public_key\': \'-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7duCMX2lDbj0KiC3fODqQp3oDXHoVvUa\nVOgbxNMo73cjgiJFtHo9T2UZZxu/bAEZ81ZF4pHryv1TK5VUcqprKTlPYDSj1n6A\nzYQVz/mV5Ou4eZOOBhoovV5YwJUJo2yW\n-----END PUBLIC KEY-----\n\', \'user_id\': \'1\'}"'

    result = bytes_to_json(val)
    assert isinstance(result, dict)


def test_format_topic():

    assert format_topic(1, 4, "user") == f"u:1/d:4/"
    assert format_topic(5, 23, "device") == f"d:5/u:23/"
    with pytest.raises(Exception):
        assert format_topic(5, 23, "invalid")
