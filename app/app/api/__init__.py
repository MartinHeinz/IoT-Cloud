from flask import Blueprint

api = Blueprint('api', __name__)

from . import endpoints, utils  # noqa pylint: disable=wrong-import-position
