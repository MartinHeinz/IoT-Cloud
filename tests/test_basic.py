# -*- coding: utf-8 -*-
from unittest.mock import Mock

from paho.mqtt.client import MQTTMessage, Client
from sqlalchemy.exc import SADeprecationWarning

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
    rv = client.get('/')
    assert int(rv.data) == 0


def test_abe():
    from .context import ABE_main
    assert ABE_main.test_abe() is True
