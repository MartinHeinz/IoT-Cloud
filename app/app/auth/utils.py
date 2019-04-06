import datetime
import json
from functools import wraps

import requests
from flask import request, current_app
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, SignatureExpired, BadSignature)
from passlib.hash import bcrypt

from app.utils import http_json_response
from app.app_setup import db
from app.models.models import User, AttrAuthUser

INVALID_ACCESS_TOKEN_ERROR_MSG = "The Access Token you provided is invalid."


def generate_auth_token(id_, token, expiration=600):
    s = Serializer(current_app.config['SECRET_KEY'], expires_in=3155760000)  # 10 years
    return s.dumps({'id': id_, 'token': token})


def handle_authorize(remote, token, user_info):
    token = save_user(remote, user_info, token).decode()
    return http_json_response(**{'access_token': token})


def save_user(remote, user_info, token):
    user = get_user(remote, user_info)
    if user is None:
        if remote.name == "github":
            user = User(id=user_info["sub"], name=user_info["preferred_username"], email=parse_email(query_github_api(token["access_token"])))
        else:
            user = AttrAuthUser(id=user_info["sub"], name=user_info["preferred_username"])

    db.session.flush()
    user.access_token = bcrypt.using(rounds=13).hash(token["access_token"])
    user.access_token_update = datetime.datetime.utcnow()
    db.session.add(user)
    db.session.commit()

    return generate_auth_token(user.id, token["access_token"])


def get_user(remote, user_info):
    if remote.name == "github":
        return db.session.query(User).filter(User.id == user_info["sub"]).first()
    return db.session.query(AttrAuthUser).filter(AttrAuthUser.id == user_info["sub"]).first()


def parse_email(response):
    json_data = json.loads(response.content.decode("utf-8"))
    for email in json_data:
        if email["primary"]:
            return email["email"]
    raise Exception("Missing primary email.")


def query_github_api(token):
    return requests.get('https://api.github.com/user/emails', headers={'Authorization': f'token {token}'})


def require_api_token(bind=None):
    def do_require_api_token(func):
        @wraps(func)
        def check_token(*args, **kwargs):
            token = request.headers.get("Authorization", "")
            if not validate_token(bind, token):
                return http_json_response(False, 400, **{"error": INVALID_ACCESS_TOKEN_ERROR_MSG})
            return func(*args, **kwargs)

        return check_token

    return do_require_api_token


def validate_token(bind, token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        return False  # valid token, but expired
    except BadSignature:
        return False  # invalid token
    if bind is None:
        user = User.get_by_id(data['id'])
    else:
        user = AttrAuthUser.get_by_id(data['id'])

    if user is not None:
        return bcrypt.verify(data["token"], user.access_token)
    return False
