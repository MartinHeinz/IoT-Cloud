from ..main import app
from ..api import api

from flask_mqtt import Mqtt
from flask_sqlalchemy import SQLAlchemy

app.config['MQTT_BROKER_URL'] = '192.168.0.103'
app.config['MQTT_BROKER_PORT'] = 3883
app.config['MQTT_USERNAME'] = ''
app.config['MQTT_PASSWORD'] = ''
app.config['MQTT_REFRESH_TIME'] = 1.0  # refresh time in seconds

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres+psycopg2://postgres:postgres@192.168.0.103/flask_test'

mqtt = Mqtt(app)
db = SQLAlchemy(app)

from app.mqtt import mqtt  # this has to be here for MQTT module to work
# TODO change to Blueprint?


