# -*- coding: utf-8 -*-
from sqlalchemy.exc import SADeprecationWarning
from .context import create_app

import pytest
import warnings


@pytest.fixture
def client():
    # TODO create and fill DB
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app('testing')
    return app.test_client()

# TODO test MQTT


def test_index(client):
    rv = client.get('/')
    assert int(rv.data) == 1
