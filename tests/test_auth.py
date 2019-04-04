import json
from datetime import datetime
from unittest import mock
from unittest.mock import Mock

import pytest
from passlib.hash import bcrypt

from app.auth.utils import parse_email, validate_token, save_user, require_api_token, INVALID_ACCESS_TOKEN_ERROR_MSG, generate_auth_token
from app.models.models import User, AttrAuthUser, Device
from .conftest import db, assert_got_data_from_post


def test_parse_email_valid():
    response = Mock()
    response.content = b'[{"email":"mail@gmail.com",' \
                       b'"primary":true,"verified":true,' \
                       b'"visibility":"public"},' \
                       b'{"email":"student@uni.com",' \
                       b'"primary":false,' \
                       b'"verified":true,' \
                       b'"visibility":null}]'
    assert parse_email(response) == "mail@gmail.com"


def test_parse_email_throws_in_missing_primary():
    response = Mock()
    response.content = b'[{"email":"mail@gmail.com",' \
                       b'"primary":false,' \
                       b'"verified":true,' \
                       b'"visibility":"public"},' \
                       b'{"email":"student@uni.com",' \
                       b'"primary":false,"verified":true,' \
                       b'"visibility":null}]'
    with pytest.raises(Exception):
        parse_email(response)
    response.content = b'nothing'
    with pytest.raises(Exception):
        parse_email(response)


def test_validate_token(app_and_ctx, access_token):
    app, ctx = app_and_ctx
    with app.app_context():
        assert validate_token(None, access_token)
        assert validate_token(None, "5c36ab84439c45a37196dftgd9bd7b31929afd9f") is False  # Not in generated schema


def test_save_user_github(app_and_ctx):
    response = Mock()
    remote = Mock()
    remote.name = "github"
    response.content = b'[{"email":"mail@gmail.com",' \
                       b'"primary":true,"verified":true,' \
                       b'"visibility":"public"},' \
                       b'{"email":"student@uni.com",' \
                       b'"primary":false,' \
                       b'"verified":true,' \
                       b'"visibility":null}]'
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
            save_user(remote, user_info, token)
            user = db.session.query(User).filter(User.id == user_info["sub"]).first()
            assert user is not None
            assert bcrypt.verify(token["access_token"], user.access_token)
            assert user.id == int(user_info["sub"])
            assert user.email is not None

            token_update_time = user.access_token_update
            save_user(remote, user_info, token)
            user = db.session.query(User).filter(User.id == user_info["sub"]).first()
            assert token_update_time < user.access_token_update


def test_save_user_stackoverflow(app_and_ctx):
    remote = Mock()
    remote.name = "stackoverflow"
    user_info = {'sub': '9155836',
                 'name': 'MartinHeinz',
                 'preferred_username': 'MartinHeinz',
                 'profile': 'https://stackoverflow.com/users/9155836/martinheinz',
                 'picture': 'https://www.gravatar.com/avatar/fb90f0e997305cfcf318f2edfd411d17?s=128&d=identicon&r=PG&f=1',
                 'address': 'Bratislava, Slovakia',
                 'updated_at': 1514634372}
    token = {'access_token': '5BagPrfZ8V9PEyyBNkjFvA))',  # Not present
             'token_type': 'Bearer'}
    app, ctx = app_and_ctx
    with app.app_context():
        user = db.session.query(AttrAuthUser).filter(AttrAuthUser.id == user_info["sub"]).first()
        assert user is None
        save_user(remote, user_info, token)
        user = db.session.query(AttrAuthUser).filter(AttrAuthUser.id == user_info["sub"]).first()
        user_github = db.session.query(User).filter(User.id == user_info["sub"]).first()
        assert user is not None
        assert user_github is None
        assert bcrypt.verify(token["access_token"], user.access_token)
        assert user.id == int(user_info["sub"])


def test_require_api_token_in_base_db(application, access_token):
    func = Mock()
    decorated_func = require_api_token(None)(func)
    with application.test_request_context("/", headers={"Authorization": "Missing"}):
        json_data = json.loads(decorated_func()[0].data.decode("utf-8"))
        assert INVALID_ACCESS_TOKEN_ERROR_MSG == json_data["error"]
    with application.test_request_context("/", headers={"Authorization": access_token}):
        decorated_func()
        assert func.call_count == 1


def test_require_api_token_in_attr_auth_db(application):
    remote = Mock()
    remote.name = "stackoverflow"
    user_info = {'sub': '34566567',
                 'name': 'Test',
                 'preferred_username': 'Test',
                 'profile': '',
                 'picture': '',
                 'address': '',
                 'updated_at': 1514634372}
    token = {'access_token': '5BagPr4ZdV9PvyyBNkjFvA))',  # Not present
             'token_type': 'Bearer'}
    func = Mock()
    decorated_func = require_api_token("attr_auth")(func)
    with application.test_request_context("/", headers={"Authorization": "Missing"}):
        json_data = json.loads(decorated_func()[0].data.decode("utf-8"))
        assert INVALID_ACCESS_TOKEN_ERROR_MSG == json_data["error"]
    with application.test_request_context("/", headers={"Authorization": "nothing-yet"}):
        decorated_func()
        assert func.call_count == 0
    token = save_user(remote, user_info, token)
    with application.test_request_context("/", headers={"Authorization": token}):
        decorated_func()
        assert func.call_count == 1


# noinspection PyArgumentList
def test_delete_account(client, app_and_ctx):
    server_data = {}
    aa_data = {}
    server_provider_token = "server_token"
    aa_provider_token = "aa_token"

    device_id = 99999
    token_hash = bcrypt.using(rounds=13).hash(server_provider_token)
    aa_token_hash = bcrypt.using(rounds=13).hash(aa_provider_token)

    user = User(
        access_token=token_hash,
        access_token_update=datetime.now(),
        owned_devices=[Device(id=device_id, name=b"test", correctness_hash="")]
    )
    aa_user = AttrAuthUser(
        access_token=aa_token_hash,
        access_token_update=datetime.now())

    db.session.add(aa_user)
    db.session.add(user)
    db.session.commit()

    app, ctx = app_and_ctx

    with app.app_context():
        server_data["access_token"] = generate_auth_token(user.id, server_provider_token)
        aa_data["access_token"] = generate_auth_token(user.id, aa_provider_token)

    assert db.session.query(User).filter(User.access_token == token_hash).first() is not None
    assert db.session.query(Device).filter(Device.id == device_id).first() is not None
    assert db.session.query(AttrAuthUser).filter(AttrAuthUser.access_token == aa_token_hash).first() is not None

    assert_got_data_from_post(client, '/delete_account', server_data)
    assert_got_data_from_post(client, '/attr_auth/delete_account', aa_data)

    assert db.session.query(User).filter(User.access_token == token_hash).first() is None
    assert db.session.query(Device).filter(Device.id == device_id).first() is None
    assert db.session.query(AttrAuthUser).filter(AttrAuthUser.access_token == aa_token_hash).first() is None


def test_redirect_to_provider(client):
    response = client.get('/login')
    assert "https://github.com/login/oauth/" in response.location
    response = client.get('/attr_auth/login')
    assert "https://stackoverflow.com/oauth" in response.location
