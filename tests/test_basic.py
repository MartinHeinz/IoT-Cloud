# -*- coding: utf-8 -*-
import base64
import json
import pytest
from paho.mqtt.client import MQTTMessage

from app.api.endpoints import DEVICE_TYPE_ID_MISSING_ERROR_MSG, DEVICE_TYPE_ID_INCORRECT_ERROR_MSG, DEVICE_NAME_BI_MISSING_ERROR_MSG, \
    DATA_RANGE_MISSING_ERROR_MSG, DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG
from app.errors.errors import SOMETHING_WENT_WRONG_MSG
from app.models.models import DeviceType, Device, DeviceData
from app.app_setup import client as mqtt_client
from client.crypto_utils import encrypt, hash

from .conftest import db
from tests.test_utils.utils import is_valid_uuid


def test_mqtt_client(app):
    assert mqtt_client._ssl is True


def test_mqtt_on_message(app):
    msg = MQTTMessage(topic=b"not_save_data")
    msg.payload = b"{'device_id': 111111, 'device_data': 'test_data'}"  # not present yet
    from app.mqtt.mqtt import handle_on_message
    app, ctx = app
    with app.app_context():
        device_data_count = db.session.query(DeviceData).count()

        handle_on_message(None, None, msg, app, db)
        assert device_data_count == db.session.query(DeviceData).count()  # 0 == 0
        msg.topic = b"save_data"
        assert device_data_count == db.session.query(DeviceData).count()  # 0 == 0
        db.session.add(Device(id=111111))
        db.session.commit()
        msg.payload = b"{'device_id': 111111, 'device_data': 'test_data'}"
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


def test_api_dt_create(client):
    data = {"description": "non-empty"}
    response = client.post('/api/device_type/create', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert is_valid_uuid(json_data["type_id"])

    data = {"not-description": "non-empty"}
    response = client.post('/api/device_type/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400


def test_api_dv_create(client, app):
    data = {"not-type_id": "non-empty"}
    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_TYPE_ID_MISSING_ERROR_MSG

    data = {"type_id": "non-valid - not present in DB"}  # TODO ERROR:  invalid input syntax for type uuid: "non-valid - not present in DB" at character 184
    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_TYPE_ID_INCORRECT_ERROR_MSG

    app, ctx = app

    with app.app_context():
        dt = DeviceType()
        db.session.add(dt)
        db.session.commit()
        data = {"type_id": str(dt.type_id)}

    response = client.post('/api/device/create', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert "id" in json_data


def test_api_get_device_by_name(client, app):
    data = {"not-name_bi": "non-empty"}
    response = client.post('/api/device/get', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DEVICE_NAME_BI_MISSING_ERROR_MSG

    data = {"name_bi": "non-empty"}
    response = client.post('/api/device/get', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["devices"] == []

    app, ctx = app

    bi_hash = "$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq"
    with app.app_context():
        dt = DeviceType(id=123)
        db.session.add(dt)
        dv = Device(id=1000,
                    status=False,
                    device_type=dt,
                    name="my_raspberry",
                    name_bi=bi_hash)
        db.session.add(dv)
        db.session.commit()
        data = {"name_bi": bi_hash}

    response = client.post('/api/device/get', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    devices = list(filter(lambda d: d["id"] == 23, json_data["devices"]))
    assert len(devices) == 1


def test_api_get_device_data_by_range_missing_bounds(client, app):
    data = {"not-upper-or-lower": "non-empty"}
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DATA_RANGE_MISSING_ERROR_MSG


def test_api_get_device_data_by_range_non_numeric_bound(client, app):
    data = {"lower": "non-numeric"}
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == DATA_RANGE_MISSING_ERROR_MSG


def test_api_get_device_data_by_range_with_only_lower_bound(client, app):
    data = {"lower": "163081415"}  # 2500
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 2


def test_api_get_device_data_by_range_with_only_upper_bound(client, app):
    data = {"upper": "228366930"}  # 3500
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 3


def test_api_get_device_data_by_range_with_both_bounds(client, app):
    data = {
        "lower": "110284915",  # 1700
        "upper": "262690267"  # 4000
            }
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 2

    data = {
        "lower": "329390554",  # 5000
        "upper": "787663574"  # 12000
    }
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    assert len(json_data["device_data"]) == 0


def test_api_get_device_data_by_range_out_of_range(client, app):
    data = {"upper": "2147483648"}  # (2^31-1) + 1
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG
    data = {"lower": "-1"}  # -1
    response = client.post('/api/data/get_time_range', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert json_data["error"] == DATA_OUT_OF_OUTPUT_RANGE_ERROR_MSG
    data = {"lower": "1", "upper": "2147483648"}  # lower OK, upper not OK
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
