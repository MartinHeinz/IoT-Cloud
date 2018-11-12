# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
	print("Connected with result code " + str(rc), flush=True)

	# Subscribing in on_connect() means that if we lose the connection and
	# reconnect then subscriptions will be renewed.
	client.subscribe("#")
	return "Connected."


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
	print("Received message '" + str(msg.payload) + "' on topic '" + msg.topic + "' with QoS " + str(msg.qos), flush=True)
	if msg.topic == "save_data":
			print("Data incoming...")
			# TODO look up device in DB based on device_id in payload -> add testing device and its type to populate.sql
			# TODO if found insert encrypted data to DB
	return "Received message."


def on_log(client, userdata, level, buf):
	print("[ON LOG]: level: {} data: {}".format(level, buf), flush=True)


def on_publish(client, userdata, mid):
	print("[ON PUBLISH]: userdata: {}  mid: {}".format(userdata, mid), flush=True)
