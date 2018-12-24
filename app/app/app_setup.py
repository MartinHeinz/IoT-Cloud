import atexit
import ssl
import os
import paho.mqtt.client as mqtt

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from app.config import config

db = SQLAlchemy()
client = mqtt.Client()


def register_models():
    from app.models.models import Device, DeviceType, User, DeviceData, Action, Scene  # noqa pylint: disable=unused-variable, cyclic-import


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    print("USING CONFIGURATION TYPE: " + config_name, flush=True)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # not using sqlalchemy event system, hence disabling it

    from .cli import populate
    app.cli.add_command(populate)

    config[config_name].init_app(app)

    db.init_app(app)
    from app.auth import oauth
    oauth.init_app(app)

    # Set up extensions
    register_models()

    dir_path = os.path.dirname(os.path.realpath(__file__))
    print("WORKING DIR: " + dir_path, flush=True)

    with app.app_context():
        db.drop_all()
        db.create_all()
        with open(app.config["POPULATE_PATH"], 'r') as sql:
            db.engine.execute(sql.read())
        db.session.commit()

    # Create app blueprints
    from app.api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix="/api")

    from app.attribute_authority import attr_authority as aa_blueprint
    app.register_blueprint(aa_blueprint, url_prefix="/attr_auth")

    from app.web import web as web_blueprint
    app.register_blueprint(web_blueprint, url_prefix="/")

    from app.auth import login as login_blueprint
    app.register_blueprint(login_blueprint, url_prefix='/')

    from app.errors import errors
    app.register_error_handler(Exception, errors.handle_error)

    from app.mqtt import handle_on_connect, handle_on_log, handle_on_publish, handle_on_message

    def on_connect(mqtt_client, userdata, flags, rc):
        handle_on_connect(mqtt_client, userdata, flags, rc)

    def on_log(mqtt_client, userdata, level, buf):
        handle_on_log(mqtt_client, userdata, level, buf)

    def on_publish(mqtt_client, userdata, mid):
        handle_on_publish(mqtt_client, userdata, mid)

    def on_message(mqtt_client, userdata, msg):
        handle_on_message(mqtt_client, userdata, msg, app, db)

    client.on_connect = on_connect
    client.on_log = on_log
    client.on_publish = on_publish
    client.on_message = on_message

    try:
        client.tls_set(ca_certs=app.config["CA_CERTS_PATH"],
                       certfile=app.config["CLIENT_CERTFILE_PATH"],
                       keyfile=app.config["CLIENT_KEYFILE_PATH"],
                       tls_version=ssl.PROTOCOL_TLSv1_2)
        client.tls_insecure_set(app.config["SSL_INSECURE"])
    except ValueError as e:
        print(e)
    client.connect(app.config["MQTT_BROKER_URL"], app.config["MQTT_BROKER_PORT"], 60)
    print("Client connected...", flush=True)

    scheduler = BackgroundScheduler()
    scheduler.add_job(func=client.loop, trigger="interval", seconds=3)
    scheduler.start()

    # Shut down the scheduler when exiting the app
    atexit.register(scheduler.shutdown)

    return app
