from authlib.common.security import generate_token
from flask import request, url_for, current_app, session

from app.auth import remote, nonce_key, backend, login
from app.auth.utils import handle_authorize


@login.route('/auth')
def auth():
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


@login.route('/login')
def login():
    redirect_uri = url_for('.auth', _external=True, _scheme='https')
    conf_key = '{}_AUTHORIZE_PARAMS'.format(backend.OAUTH_NAME.upper())
    params = current_app.config.get(conf_key, {})
    if 'oidc' in backend.OAUTH_TYPE:
        nonce = generate_token(20)
        session[nonce_key] = nonce
        params['nonce'] = nonce
    return remote.authorize_redirect(redirect_uri, **params)