from app.app_setup import mqtt

@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    mqtt.subscribe('flask_test')


@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    data = dict(
        topic=message.topic,
        payload=message.payload.decode()
    )
    print(data["payload"])
