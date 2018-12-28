from flask import Blueprint
from authlib.flask.client import RemoteApp, OAuth

from ._core import register_to
from .github import GitHub
from .stackapps import StackOverflow


OAUTH_BACKENDS = [
    GitHub,
    StackOverflow
]

__all__ = [
    'register_to',
    'GitHub',
    'OAUTH_BACKENDS',
    'login',
    'nonce_key',
    'backend',
    'remote',
    'oauth',

    'StackOverflow',
    'login_aa',
    'nonce_key_aa',
    'backend_aa',
    'remote_aa',
    'oauth_aa',
]

oauth = OAuth()
backend = GitHub
remote = register_to(backend, oauth, RemoteApp)
nonce_key = '_{}:nonce'.format(backend.OAUTH_NAME)
login = Blueprint('auth_' + backend.OAUTH_NAME, __name__)

oauth_aa = OAuth()
backend_aa = StackOverflow
remote_aa = register_to(backend_aa, oauth_aa, RemoteApp)
nonce_key_aa = '_{}:nonce'.format(backend_aa.OAUTH_NAME)
login_aa = Blueprint('auth_' + backend_aa.OAUTH_NAME, __name__ + "_aa")

from . import utils, _flask  # noqa pylint: disable=wrong-import-position
