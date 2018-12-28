import json
from unittest import mock
from unittest.mock import Mock

import pytest

from app.auth.utils import parse_email, validate_token, save_user, require_api_token, INVALID_ACCESS_TOKEN_ERROR_MSG
from app.models.models import User
from .conftest import db


def test_parse_email_valid():
    response = Mock()
    response.content = b'[{"email":"mail@gmail.com","primary":true,"verified":true,"visibility":"public"},{"email":"student@uni.com","primary":false,"verified":true,"visibility":null}]'
    assert parse_email(response) == "mail@gmail.com"


def test_parse_email_throws_in_missing_primary():
    response = Mock()
    response.content = b'[{"email":"mail@gmail.com","primary":false,"verified":true,"visibility":"public"},{"email":"student@uni.com","primary":false,"verified":true,"visibility":null}]'
    with pytest.raises(Exception):
        parse_email(response)
    response.content = b'nothing'
    with pytest.raises(Exception):
        parse_email(response)


def test_validate_token(app_and_ctx, access_token):
    app, ctx = app_and_ctx
    with app.app_context():
        assert validate_token(access_token)
        assert validate_token("5c36ab84439c45a37196dftgd9bd7b31929afd9f") is False  # Not in generated schema


def test_save_user(app_and_ctx):
    response = Mock()
    response.content = b'[{"email":"mail@gmail.com","primary":true,"verified":true,"visibility":"public"},{"email":"student@uni.com","primary":false,"verified":true,"visibility":null}]'
    user_info = {'sub': '456456',  # Made-up
                 'name': None,
                 'email': None,
                 'preferred_username': 'UserName',
                 'picture': 'https://avatars0.githubusercontent.com/u/11890454?v=4', 'website': ''}
    token = {'access_token': '5c36ab840e9c45a3719dfbc0d9fe7b3192923v9f',  # Not present
             'token_type': 'bearer', 'scope': 'user:email'}
    app, ctx = app_and_ctx
    with app.app_context():
        with mock.patch('app.auth.utils.query_github_api', return_value=response):
            user = db.session.query(User).filter(User.id == user_info["sub"]).first()
            assert user is None
            save_user(user_info, token)
            user = db.session.query(User).filter(User.id == user_info["sub"]).first()
            assert user is not None
            assert user.access_token == token["access_token"]
            assert user.id == int(user_info["sub"])

            token_update_time = user.access_token_update
            save_user(user_info, token)
            user = db.session.query(User).filter(User.id == user_info["sub"]).first()
            assert token_update_time < user.access_token_update


def test_require_api_token(application):
    func = Mock()
    decorated_func = require_api_token(func)
    with application.test_request_context("/?access_token=Missing"):
        json_data = json.loads(decorated_func()[0].data.decode("utf-8"))
        assert INVALID_ACCESS_TOKEN_ERROR_MSG == json_data["error"]
    with application.test_request_context("/?access_token=5c36ab84439c45a3719644c0d9bd7b31929afd9f"):
        decorated_func()
        assert func.call_count == 1



