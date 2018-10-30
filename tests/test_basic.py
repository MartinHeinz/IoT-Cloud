# -*- coding: utf-8 -*-
import base64
from unittest.mock import Mock

from paho.mqtt.client import MQTTMessage, Client
from sqlalchemy.exc import SADeprecationWarning

from client.crypto_utils import encrypt
from .context import create_app, db

import pytest
import warnings


@pytest.fixture
def client():
	warnings.filterwarnings("ignore", category=SADeprecationWarning)
	app = create_app('testing')
	with app.app_context():
		db.create_all()
	return app.test_client()


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
		b"{'data': 'secret'}",
		b"authenticated but not encrypted payload"
	)
	response = client.post('/api/publish', query_string=dict(
		ciphertext=str(base64.b64encode(ciphertext), 'utf-8'),
		tag=str(base64.b64encode(tag), 'utf-8'),
		topic="flask_test"
	), follow_redirects=True)

	assert response.status_code == 200


def test_abe():
	from .context import ABE_main
	assert ABE_main.test_abe() is True
