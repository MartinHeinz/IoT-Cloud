from flask import Blueprint

mq = Blueprint('mq', __name__)

from . import mqtt
