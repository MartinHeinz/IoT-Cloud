import atexit

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

import paho.mqtt.client as mqtt
from app.mqtt.mqtt import on_connect, on_message

from app.config import config

db = SQLAlchemy()
client = mqtt.Client()


def create_app(config_name):
	app = Flask(__name__)
	app.config.from_object(config[config_name])
	print("USING CONFIGURATION TYPE: " + config_name, flush=True)
	app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
	# not using sqlalchemy event system, hence disabling it

	config[config_name].init_app(app)

	db.init_app(app)
	# Set up extensions
	from app.models.models import Device, DeviceType, User
	with app.app_context():
		db.drop_all()
		db.create_all()
		db.session.commit()

	# Create app blueprints

	from app.api import api as api_blueprint
	app.register_blueprint(api_blueprint, url_prefix="/api")

	from app.web import web as web_blueprint
	app.register_blueprint(web_blueprint, url_prefix="/")

	client.on_connect = on_connect
	client.on_message = on_message

	client.connect(app.config["MQTT_BROKER_URL"], app.config["MQTT_BROKER_PORT"], 60)
	print("Client connected...", flush=True)

	scheduler = BackgroundScheduler()
	scheduler.add_job(func=client.loop, trigger="interval", seconds=3)
	scheduler.start()

	# Shut down the scheduler when exiting the app
	atexit.register(lambda: scheduler.shutdown())

	return app
