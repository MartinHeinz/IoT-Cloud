# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc), flush=True)

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("flask_test")
    return "Connected."


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print("Received message '" + str(msg.payload) + "' on topic '" + msg.topic + "' with QoS " + str(msg.qos), flush=True)
    return "Received message."
