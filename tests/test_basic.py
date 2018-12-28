# -*- coding: utf-8 -*-
import base64
import json
from uuid import UUID

import pytest
from paho.mqtt.client import MQTTMessage

from app.api.endpoints import DEVICE_TYPE_ID_MISSING_ERROR_MSG, DEVICE_TYPE_ID_INCORRECT_ERROR_MSG, DEVICE_NAME_BI_MISSING_ERROR_MSG, \
    DATA_RANGE_MISSING_ERROR_MSG, DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG, DEVICE_NAME_MISSING_ERROR_MSG, CORRECTNESS_HASH_MISSING_ERROR_MSG
from app.errors.errors import SOMETHING_WENT_WRONG_MSG
from app.models.models import DeviceType, Device, DeviceData
from app.app_setup import client as mqtt_client
from app.mqtt.utils import Payload
from app.utils import is_valid_uuid
from client.crypto_utils import encrypt, hash, correctness_hash
from passlib.hash import bcrypt

from .conftest import db


def test_mqtt_client(app_and_ctx):
    assert mqtt_client._ssl is True


def test_mqtt_on_message(app_and_ctx):
    msg = MQTTMessage(topic=b"not_save_data")
    msg.payload = bytes(Payload(device_id=111111,
                                device_data='test_data'))  # not present yet
    from app.mqtt.mqtt import handle_on_message
    app, ctx = app_and_ctx
    with app.app_context():
        device_data_count = db.session.query(DeviceData).count()

        handle_on_message(None, None, msg, app, db)
        assert device_data_count == db.session.query(DeviceData).count()  # 0 == 0
        msg.topic = b"save_data"
        assert device_data_count == db.session.query(DeviceData).count()  # 0 == 0
        db.session.add(Device(id=111111, name="testingDevice", correctness_hash=correctness_hash("testingDevice")))
        db.session.commit()
        msg.payload = bytes(Payload(device_id=111111,
                                    device_data='test_data',
                                    added='2017-12-11 17:12:34',
                                    num_data=840125,
                                    correctness_hash='$2b$12$5s/6DQkc3Tkq.9dXQ9fK/usP1usuyQh1rpsh5dBCQee8UXdVI7.6e'))
        handle_on_message(None, None, msg, app, db)
        assert device_data_count + 1 == db.session.query(DeviceData).count()  # 0 + 1 == 1


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
    assert (json_data["error"]) == DEVICE_NAME_BI_MISSING_ERROR_MSG

    data = {
        "type_id": "non-valid",
        "access_token": access_token,
        "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
        "name": "test",
        "name_bi": "$2b$12$1xxxxxxxxxxxxxxxxxxxxuDUX01AKuyu/3/PdSxQT4qMDVTUawIUq"
    }
    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_TYPE_ID_INCORRECT_ERROR_MSG

    app, ctx = app_and_ctx

    with app.app_context():
        dt = DeviceType(description="nothing.....", correctness_hash=correctness_hash("nothing....."))
        db.session.add(dt)
        db.session.commit()
        data = {
            "type_id": str(dt.type_id),
            "access_token": access_token,
            "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
            "name": "test",
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
        dt = DeviceType(id=123, description="nothing...", correctness_hash=correctness_hash("nothing..."))
        db.session.add(dt)
        dv = Device(id=1000,
                    status=False,
                    device_type=dt,
                    name="my_raspberry",
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


def test_api_get_device_data_by_range_missing_bounds(client, app_and_ctx, access_token):
    data = {"not-upper-or-lower": "non-empty", "access_token": access_token}
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DATA_RANGE_MISSING_ERROR_MSG


def test_api_get_device_data_by_range_non_numeric_bound(client, app_and_ctx, access_token):
    data = {"lower": "non-numeric", "access_token": access_token}
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DATA_RANGE_MISSING_ERROR_MSG


def test_api_get_device_data_by_range_with_only_lower_bound(client, app_and_ctx, access_token):
    data = {"lower": "163081415", "access_token": access_token}  # 2500
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 2


def test_api_get_device_data_by_range_with_only_upper_bound(client, app_and_ctx, access_token):
    data = {"upper": "228366930", "access_token": access_token}  # 3500
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 3


def test_api_get_device_data_by_range_with_both_bounds(client, app_and_ctx, access_token):
    data = {
        "lower": "110284915",  # 1700
        "upper": "262690267",  # 4000
        "access_token": access_token
            }
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 2

    data = {
        "lower": "329390554",  # 5000
        "upper": "787663574",  # 12000
        "access_token": access_token
    }
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 0


def test_api_get_device_data_by_range_out_of_range(client, app_and_ctx, access_token):
    data = {"upper": "2147483648", "access_token": access_token}  # (2^31-1) + 1
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG
    data = {"lower": "-1", "access_token": access_token}  # -1
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG
    data = {"lower": "1", "upper": "2147483648", "access_token": access_token}  # lower OK, upper not OK
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG


def test_abe():
    from .context import ABE_main
    assert ABE_main.test_abe() is True


def test_hash_bcrypt():
    assert hash("raspberry", "1234srfh") == "$2b$12$1234srfhxxxxxxxxxxxxxu9oRez2BjitmNvretimcFcTsuR/HtxQa"
    with pytest.raises(Exception):
        hash("raspberry", "")


def test_correctness_hash():
    assert bcrypt.verify("ergh" + "esrge", correctness_hash("ergh", "esrge"))
    assert bcrypt.verify("ergh" + "esrge" + "1", correctness_hash("ergh", "esrge", fake=True))
    assert not bcrypt.verify("ergh" + "esrge" + "wes", correctness_hash("ergh", "esrge"))
