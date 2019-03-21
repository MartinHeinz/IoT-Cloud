from authlib.common.security import generate_token
from flask import request, url_for, current_app, session

from app.app_setup import db
from app.auth import login, login_aa, remote_aa, nonce_key_aa, backend_aa
from app.auth import remote as remote_app, nonce_key as nonce_key_app, backend as backend_app
from app.auth.utils import handle_authorize, token_to_hash
from app.models.models import AttrAuthUser, User
from app.utils import http_json_response


@login_aa.route('/delete_account', methods=['POST'])
def delete_account_aa():  # TODO Check if user exists
    user = AttrAuthUser.get_by_access_token(token_to_hash(request.headers.get('Authorization', "")))
    db.session.delete(user)
    db.session.commit()

    return http_json_response()


@login.route('/delete_account', methods=['POST'])
def delete_account():  # TODO Check if user exists
    user = User.get_by_access_token(token_to_hash(request.headers.get('Authorization', "")))
    db.session.delete(user)
    db.session.commit()

    return http_json_response()


@login.route('/auth')
def auth():
    return auth_common(remote_app, nonce_key_app)


@login.route('/login')
def login():  # noqa pylint: disable=function-redefined
    return login_common(remote_app, ".auth", backend_app, nonce_key_app)


@login_aa.route('/auth')
def auth_aa():
    return auth_common(remote_aa, nonce_key_aa)


@login_aa.route('/login')
def login_aa():  # noqa pylint: disable=function-redefined
    return login_common(remote_aa, ".auth_aa", backend_aa, nonce_key_aa)


def login_common(remote, url_for_auth, backend, nonce_key):
    redirect_uri = url_for(url_for_auth, _external=True, _scheme='https')
    conf_key = '{}_AUTHORIZE_PARAMS'.format(backend.OAUTH_NAME.upper())
    params = current_app.config.get(conf_key, {})
    if 'oidc' in backend.OAUTH_TYPE:
        nonce = generate_token(20)
        session[nonce_key] = nonce
        params['nonce'] = nonce
    return remote.authorize_redirect(redirect_uri, **params)


def auth_common(remote, nonce_key):
    id_token = request.args.get('id_token')
    if request.args.get('code'):
        token = remote.authorize_access_token()
        if id_token:
            token['id_token'] = id_token
    elif id_token:
        token = {'id_token': id_token}
    elif request.args.get('oauth_verifier'):
        # OAuth 1
        token = remote.authorize_access_token()
    else:
        # handle failed
        return handle_authorize(remote, None, None)
    if 'id_token' in token:
        nonce = session[nonce_key]
        user_info = remote.parse_openid(token, nonce)
    else:
        user_info = remote.profile(token=token)
    return handle_authorize(remote, token, user_info)
