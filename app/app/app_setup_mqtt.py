from flask import Flask

from app.config import config

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()

import paho.mqtt.client as mqtt

client = mqtt.Client()


# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc), flush=True)

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("flask_test")


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload), flush=True)


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    print("USING CONFIGURATION TYPE: " + config_name, flush=True)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # not using sqlalchemy event system, hence disabling it

    config[config_name].init_app(app)

    # Set up extensions
    db.init_app(app)

    client.on_connect = on_connect
    client.on_message = on_message

    client.connect("192.168.0.102", 3883, 60)
    print("Client connected...", flush=True)

    return app
