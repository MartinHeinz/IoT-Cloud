from flask import current_app
from sqlalchemy import and_

from app.api.utils import is_number
from app.models.models import Device, DeviceData, User
from app.mqtt.utils import Payload
from app.utils import bytes_to_json


# The callback for when the client receives a CONNACK response from the server.
def handle_on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc), flush=True)
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("#")


# The callback for when a PUBLISH message is received from the server.
def handle_on_message(client, userdata, msg, app, db):
    msg.payload = bytes_to_json(msg.payload)  # TODO sanitize this?
    print("Received message '" + str(msg.payload) + "' on topic '" + msg.topic + "' with QoS " + str(msg.qos), flush=True)

    topic = msg.topic.split("/")
    if len(topic) == 2 and topic[1] == "server":  # TODO don't trust the device, use a token to authenticate device
        _save_device_pk(topic, msg, app, db)
    elif len(topic) == 3 and topic[1] == "server":
        if topic[2] in ["save_data", "remove_data"]:
            if is_number(topic[0]):
                _edit_device_data(int(topic[0]), topic[2], msg, app, db)
            else:
                print(f"Invalid Device ID: {topic[0]}", flush=True)


def _save_device_pk(topic, msg, app, db):
    try:
        device_id = int(topic[0])
    except ValueError:
        print(f"Invalid device ID: {topic[0]}", flush=True)
        return
    payload = Payload(**msg.payload)
    with app.app_context():
        user = User.get_by_id(payload.user_id)
        user_device = next((d for d in user.devices if d.device_id == device_id), None)
        if user_device:
            user_device.device_public_session_key = payload.device_public_key
            db.session.add(user_device)
            db.session.commit()
        else:
            print(f"This User can't access device {device_id}", flush=True)


def _edit_device_data(device_id, action, msg, app, db):
    with app.app_context():
        device = db.session.query(Device).filter(Device.id == device_id).first()
        if device is not None:
            if action == "save_data":
                # noinspection PyArgumentList
                db.session.add(DeviceData(  # TODO extract this to Model class
                        tid=msg.payload["tid"],
                        data=str.encode(msg.payload["data"]),
                        device=device,
                        correctness_hash=msg.payload["correctness_hash"],
                        num_data=int(msg.payload["num_data"]),
                        added=int(msg.payload["added"])
                    ))
            else:
                db.session.query(DeviceData)\
                    .filter(and_(
                        DeviceData.tid == msg.payload["tid"],
                        DeviceData.device_id == device_id,
                    )).delete()  # TODO extract this to Model class
            db.session.commit()
        else:
            print(f"Device with id: {device_id} doesn't exist.", flush=True)


def handle_on_log(client, userdata, level, buf):
    if not current_app.testing:
        print("[ON LOG]: level: {} data: {}".format(level, buf), flush=True)


def handle_on_publish(client, userdata, mid):
    print("[ON PUBLISH]: userdata: {}  mid: {}".format(userdata, mid), flush=True)
