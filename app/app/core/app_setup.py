from app.models.user import User
from ..main import app
from ..api import api

from flask_mqtt import Mqtt
from flask_sqlalchemy import SQLAlchemy

app.config['MQTT_BROKER_URL'] = '0.0.0.0'
app.config['MQTT_BROKER_PORT'] = 2883
app.config['MQTT_USERNAME'] = ''
app.config['MQTT_PASSWORD'] = ''
app.config['MQTT_REFRESH_TIME'] = 1.0  # refresh time in seconds

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres+psycopg2://postgres:postgres@192.168.0.102/flask_test'

mqtt = Mqtt(app)
db = SQLAlchemy(app)

Hello = "Users"


@app.route('/')
def hello():
    # for u in db.session.query(User).all():
    #     temp += str(u.__dict__)
    # global Hello
    return str(db.session.query(User).count())


@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    mqtt.subscribe('flask_test')


@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    global Hello
    data = dict(
        topic=message.topic,
        payload=message.payload.decode()
    )
    Hello += data["payload"]


