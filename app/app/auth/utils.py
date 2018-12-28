import datetime
import json
from functools import wraps

import requests
from flask import request
from sqlalchemy import exists

from app.utils import http_json_response
from app.app_setup import db
from app.models.models import User

INVALID_ACCESS_TOKEN_ERROR_MSG = "The Access Token you provided is invalid."


def handle_authorize(remote, token, user_info):
    save_user(remote, user_info, token)
    return http_json_response(**{'access_token': token["access_token"]})


def save_user(remote, user_info, token):
    user = db.session.query(User).filter(User.id == user_info["sub"]).first()
    if user is None:
        user = User(id=user_info["sub"], name=user_info["preferred_username"])
        if remote.name == "github":
            user.email = parse_email(query_github_api(token["access_token"]))
    user.access_token = token["access_token"]
    user.access_token_update = datetime.datetime.utcnow()
    db.session.add(user)
    db.session.commit()


def parse_email(response):
    json_data = json.loads(response.content.decode("utf-8"))
    for email in json_data:
        if email["primary"]:
            return email["email"]
    raise Exception("Missing primary email.")


def query_github_api(token):
    return requests.get('https://api.github.com/user/emails', headers={'Authorization': f'token {token}'})


def require_api_token(func):
    @wraps(func)
    def check_token(*args, **kwargs):
        token = request.args.get("access_token", "")
        if not validate_token(token):
            return http_json_response(False, 400, **{"error": INVALID_ACCESS_TOKEN_ERROR_MSG})

        return func(*args, **kwargs)

    return check_token


def validate_token(token):
    return db.session.query(exists().where(User.access_token == token)).scalar()
