from flask import Blueprint

attr_authority = Blueprint('attr_authority', __name__)

from . import endpoints  # noqa pylint: disable=wrong-import-position
