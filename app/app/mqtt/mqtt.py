from datetime import datetime
from flask import current_app
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

    elif msg.topic == "save_data":
        with app.app_context():
            device = db.session.query(Device).filter(Device.id == msg.payload["device_id"]).first()
            print("Querying device with id: " + str(msg.payload["device_id"]), flush=True)
            if device is not None:
                db.session.add(DeviceData(
                    data=str.encode(msg.payload["device_data"]),
                    device=device,
                    correctness_hash=msg.payload["correctness_hash"],
                    num_data=msg.payload["num_data"],
                    added=datetime.strptime(msg.payload["added"], "%Y-%m-%d %H:%M:%S")
                ))
                db.session.commit()
                print("Inserting device data for device: " + str(msg.payload["device_id"]) + " data: " + msg.payload["device_data"], flush=True)
            else:
                print("Device with id: " + str(msg.payload["device_id"]) + " doesn't exist.", flush=True)


def handle_on_log(client, userdata, level, buf):
    if not current_app.testing:
        print("[ON LOG]: level: {} data: {}".format(level, buf), flush=True)


def handle_on_publish(client, userdata, mid):
    print("[ON PUBLISH]: userdata: {}  mid: {}".format(userdata, mid), flush=True)
