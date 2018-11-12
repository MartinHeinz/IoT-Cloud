# -*- coding: utf-8 -*-
import base64
import json
from unittest.mock import Mock

from paho.mqtt.client import MQTTMessage, Client

from app.api.endpoints import DEVICE_TYPE_ID_MISSING_ERROR_MSG, DEVICE_TYPE_ID_INCORRECT_ERROR_MSG
from app.models.models import DeviceType
from client.crypto_utils import encrypt

from tests.test_utils.fixtures import *
from tests.test_utils.utils import is_valid_uuid


def test_mqtt_client():
	mock = Mock(spec=Client)
	mock.subscribe.return_value(None)

	from app.mqtt.mqtt import on_connect, on_message
	assert on_message(None, None, MQTTMessage()) == "Received message."
	assert on_connect(mock, None, None, 0) == "Connected."


def test_index(client):
	response = client.get('/')
	assert "Hi from app!" in str(response.data)


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

	data = {"type_id": "non-valid - not present in DB"}
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


def test_abe():
	from .context import ABE_main
	assert ABE_main.test_abe() is True

