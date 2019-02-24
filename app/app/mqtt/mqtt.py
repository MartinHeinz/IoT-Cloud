from flask import current_app

from app.models.models import Device, DeviceData, User
from app.mqtt.utils import Payload
from app.utils import bytes_to_json, is_number


# The callback for when the client receives a CONNACK response from the server.
def handle_on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc), flush=True)
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("#")


# The callback for when a PUBLISH message is received from the server.
def handle_on_message(client, userdata, msg, app, db):
    try:
        msg.payload = bytes_to_json(msg.payload)
        print("Received message '" + str(msg.payload) + "' on topic '" + msg.topic + "' with QoS " + str(msg.qos), flush=True)
    except:
        print("Received invalid message '" + str(msg.payload) + "' on topic '" + msg.topic + "' with QoS " + str(msg.qos), flush=True)
        return
    if msg.topic.endswith("/"):
        msg.topic = msg.topic[:-1].encode()
    topic = msg.topic.split("/")
    if len(topic) >= 2 and topic[1] == "server":
        t, sender_id = topic[0].split(":")
        if t == "d" and is_number(sender_id):
            if len(topic) == 2:
                _save_device_pk(int(sender_id), msg, app, db)
            elif len(topic) == 3:
                if topic[2] in ["save_data", "remove_data"]:
                    _edit_device_data(int(sender_id), topic[2], msg, app, db)
                else:
                    print(f"Invalid topic: {msg.topic}", flush=True)
        else:
            print(f"Invalid Device type or ID", flush=True)


def _save_device_pk(sender_id, msg, app, db):
    payload = Payload(**msg.payload)
    with app.app_context():
        user = User.get_by_id(payload.user_id)
        user_device = next((d for d in user.devices if d.device_id == sender_id), None)
        if user_device:
            user_device.device_public_session_key = payload.device_public_key
            db.session.add(user_device)
            db.session.commit()
        else:
            print(f"This User can't access device {sender_id}", flush=True)


def _edit_device_data(device_id, action, msg, app, db):
    with app.app_context():
        device = db.session.query(Device).filter(Device.id == device_id).first()
        if device is not None:
            if action == "save_data":
                # noinspection PyArgumentList
                db.session.add(DeviceData(
                        tid=str.encode(msg.payload["tid"]),
                        tid_bi=msg.payload["tid_bi"],
                        data=str.encode(msg.payload["data"]),
                        device=device,
                        correctness_hash=msg.payload["correctness_hash"],
                        num_data=int(msg.payload["num_data"]),
                        added=int(msg.payload["added"])
                    ))
            else:
                DeviceData.delete_by_tid_bi(msg.payload["tid_bi"], device_id)  # TODO Doesn't check attributes only tid -> deletes even if all attrs are different
            db.session.commit()
        else:
            print(f"Device with id: {device_id} doesn't exist.", flush=True)


def handle_on_log(client, userdata, level, buf):
    if not current_app.testing:
        print("[ON LOG]: level: {} data: {}".format(level, buf), flush=True)


def handle_on_publish(client, userdata, mid):
    print("[ON PUBLISH]: userdata: {}  mid: {}".format(userdata, mid), flush=True)
