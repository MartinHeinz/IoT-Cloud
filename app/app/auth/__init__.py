from flask import Blueprint
from authlib.flask.client import RemoteApp, OAuth

from ._core import register_to
from .github import GitHub


OAUTH_BACKENDS = [
    GitHub
]

__all__ = [
    'register_to',
    'GitHub',
    'OAUTH_BACKENDS',
    'login',
    'nonce_key',
    'backend',
    'remote',
    'oauth'
]

oauth = OAuth()
backend = GitHub
remote = register_to(backend, oauth, RemoteApp)
nonce_key = '_{}:nonce'.format(backend.OAUTH_NAME)
login = Blueprint('auth_' + backend.OAUTH_NAME, __name__)

from . import utils, _flask  # noqa pylint: disable=wrong-import-position
