# -*- coding: utf-8 -*-

from .context import main

import pytest


@pytest.fixture
def client():
    # TODO create and fill DB
    main.app.config['TESTING'] = True
    main.app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres+psycopg2://postgres:postgres@localhost/flask_test'
    client = main.app.test_client()

    return client

# TODO test MQTT


def test_index(client):
    rv = client.get('/')
    assert int(rv.data) == 1
