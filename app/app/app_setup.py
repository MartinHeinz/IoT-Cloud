from flask import Flask

from app.config import config
from app.api import api

from flask_mqtt import Mqtt
from flask_sqlalchemy import SQLAlchemy

mqtt = Mqtt()
db = SQLAlchemy()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    print("USING CONFIGURATION TYPE: " + config_name, flush=True)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # not using sqlalchemy event system, hence disabling it

    config[config_name].init_app(app)

    # Set up extensions
    db.init_app(app)
    mqtt.init_app(app)

    # Create app blueprints
    from app.api.endpoints import home as home_blueprint
    app.register_blueprint(home_blueprint)

    from app.mqtt import mq as mq_blueprint
    app.register_blueprint(mq_blueprint)

    return app
