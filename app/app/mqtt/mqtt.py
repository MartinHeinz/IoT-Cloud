from app.app_setup_mqtt import mqtt

@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    print("handle_connect...", flush=True)
    mqtt.subscribe('flask_test')


@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    data = dict(
        topic=message.topic,
        payload=message.payload.decode()
    )
    print(data["payload"], flush=True)
