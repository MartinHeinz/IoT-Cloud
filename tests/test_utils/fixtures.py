import warnings

import pytest
from sqlalchemy.exc import SADeprecationWarning

from app.app_setup import create_app, db


@pytest.fixture
def client():
	warnings.filterwarnings("ignore", category=SADeprecationWarning)
	app = create_app('testing')
	return app.test_client()


@pytest.fixture
def app():
	warnings.filterwarnings("ignore", category=SADeprecationWarning)
	app = create_app('testing')
	ctx = app.app_context()
	ctx.push()
	yield app, ctx
	db.drop_all()
