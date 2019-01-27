import base64
import json
import os
import re
import ssl
import sys
from binascii import b2a_hex, a2b_hex

import click
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from paho.mqtt import client as paho
from tinydb import TinyDB, where, Query


sys.stdout = open(os.devnull, 'w')
sys.path.insert(0, '../app')
from app.api.utils import is_number
from app.utils import bytes_to_json
sys.stdout = sys.__stdout__

try:  # for packaged CLI (setup.py)
    from client.crypto_utils import hash, correctness_hash, check_correctness_hash
    from client.utils import json_string_with_bytes_to_dict, _create_payload
except ImportError:  # for un-packaged CLI
    from crypto_utils import hash, correctness_hash, check_correctness_hash
    from utils import json_string_with_bytes_to_dict, _create_payload


URL_BASE = "https://localhost/api/"
URL_PUBLISH = URL_BASE + "publish"
URL_CREATE_DEVICE_TYPE = URL_BASE + "device_type/create"
URL_CREATE_DEVICE = URL_BASE + "device/create"
URL_GET_DEVICE = URL_BASE + "device/get"
URL_GET_DEVICE_DATA_BY_RANGE = URL_BASE + "data/get_time_range"
URL_GET_DEVICE_DATA = URL_BASE + "data/get_device_data"
URL_START_KEY_EXCHANGE = URL_BASE + "exchange_session_keys"
URL_RECEIVE_PUBLIC_KEY = URL_BASE + "retrieve_public_key"

AA_URL_BASE = "https://localhost/attr_auth/"
AA_URL_SET_USERNAME = AA_URL_BASE + "set_username"
AA_URL_SETUP = AA_URL_BASE + "setup"
AA_URL_KEYGEN = AA_URL_BASE + "keygen"
AA_URL_ENCRYPT = AA_URL_BASE + "encrypt"
AA_URL_DECRYPT = AA_URL_BASE + "decrypt"

dir_path = os.path.dirname(os.path.realpath(__file__))
path = f'{dir_path}/keystore.json'


@click.group()
@click.pass_context
def user(ctx):
    global VERIFY_CERTS
    global MQTT_BROKER
    global MQTT_PORT
    VERIFY_CERTS = ctx.obj['VERIFY_CERTS']
    MQTT_BROKER = ctx.obj['BROKER']
    MQTT_PORT = ctx.obj['PORT']


@user.command()
@click.argument('device_id')
@click.argument('data')
def send_message(device_id, data):
    db = TinyDB(path)
    table = db.table(name='device_keys')
    doc = table.get(Query().device_id == device_id)

    if not doc:
        with click.Context(send_key_to_device) as ctx:
            click.echo(f"Keys for device {device_id} not present, please use: {ctx.command.name}")
            click.echo(get_attr_auth_keys.get_help(ctx))
            return

    shared_key = a2b_hex(doc["shared_key"].encode())
    fernet_key = Fernet(base64.urlsafe_b64encode(shared_key))
    token = fernet_key.encrypt(data.encode())

    client = _setup_client("user_id")  # TODO replace with actual user_id

    payload = _create_payload(1, {"ciphertext": token.decode()})
    ret = client.publish(f"1/{device_id}", payload)  # TODO replace with actual user_id, change payload to json and parse it as JSON on device end
    click.echo(f"RC and MID = {ret}")


@user.command()
@click.argument('description')
@click.option('--token', envvar='ACCESS_TOKEN')
def create_device_type(description, token):
    data = {"description": description, "access_token": token, "correctness_hash": correctness_hash(description)}
    r = requests.post(URL_CREATE_DEVICE_TYPE, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_type_id')
@click.argument('device_name')
@click.argument('user_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def create_device(device_type_id, user_id, device_name, token):
    data = {
        "type_id": device_type_id,
        "access_token": token,
        "name": device_name,
        "correctness_hash": correctness_hash(device_name),
        "name_bi": hash(device_name, user_id)}
    r = requests.post(URL_CREATE_DEVICE, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_name')
@click.argument('user_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def get_devices(device_name, user_id, token):
    device_name_bi = hash(device_name, user_id)
    data = {"name_bi": device_name_bi, "access_token": token}
    r = requests.post(URL_GET_DEVICE, params=data, verify=VERIFY_CERTS)
    content = json.loads(r.content.decode('unicode-escape'))
    check_correctness_hash(content["devices"], "name")
    click.echo(content["devices"])


@user.command()
@click.option('--lower', required=False)
@click.option('--upper', required=False)
@click.option('--token', envvar='ACCESS_TOKEN')
def get_device_data_by_time_range(lower=None, upper=None, token=""):  # TODO add decryption based on stored keys
    if lower is not None and upper is not None:
        data = {"lower": int(lower), "upper": int(upper), "access_token": token}
    elif lower is not None and upper is None:
        data = {"lower": int(lower), "access_token": token}
    elif lower is None and upper is not None:
        data = {"upper": int(upper), "access_token": token}
    else:
        data = {"lower": 0, "upper": 2147483647, "access_token": token}
    r = requests.post(URL_GET_DEVICE_DATA_BY_RANGE, params=data, verify=VERIFY_CERTS)
    content = r.content.decode('unicode-escape')
    json_content = json_string_with_bytes_to_dict(content)
    check_correctness_hash(json_content["device_data"], 'added', 'data', 'num_data')  # TODO add TID and update test and schema with correctness hashes that include TID
    click.echo(content)


@user.command()
@click.argument('device_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def send_key_to_device(device_id, token):
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    db = TinyDB(path)
    table = db.table(name='device_keys')
    table.upsert({
        'device_id': device_id,
        'public_key': public_pem,
        'private_key': private_pem
    }, Query().device_id == device_id)

    data = {
        'device_id': device_id,
        'public_key': public_pem,
        'access_token': token
    }
    r = requests.post(URL_START_KEY_EXCHANGE, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def retrieve_device_public_key(device_id, token):
    data = {
        "access_token": token,
        "device_id": device_id
    }
    db = TinyDB(path)
    table = db.table(name='device_keys')
    doc = table.get(Query().device_id == device_id)

    if not doc:
        with click.Context(send_key_to_device) as ctx:
            click.echo(f"Keys for device {device_id} not present, please use: {ctx.command.name}")
            click.echo(get_attr_auth_keys.get_help(ctx))
            return

    r = requests.post(URL_RECEIVE_PUBLIC_KEY, params=data, verify=VERIFY_CERTS)
    if r.status_code != 200:
        click.echo(r.content.decode('unicode-escape'))
        return

    content = r.content.decode('unicode-escape')
    json_content = json_string_with_bytes_to_dict(content)

    private_key = load_pem_private_key(doc["private_key"].encode(), password=None, backend=default_backend())
    assert isinstance(private_key, EllipticCurvePrivateKey), "Loading private key failed! - private_key is not instance of EllipticCurvePrivateKey"
    device_public_key = load_pem_public_key(json_content["device_public_key"].encode(), backend=default_backend())
    assert isinstance(device_public_key, EllipticCurvePublicKey), "Loading public key failed! - private_key is not instance of EllipticCurvePublicKey"
    shared_key = private_key.exchange(ec.ECDH(), device_public_key)

    key = b2a_hex(shared_key[:32]).decode()  # NOTE: retrieve key as `a2b_hex(key.encode())`
    table.remove(Query().device_id == device_id)
    table.insert({'device_id': device_id, 'shared_key': key})


@user.command()
@click.argument('device_id')
def send_column_keys(device_id):
    db = TinyDB(path)
    table = db.table(name='device_keys')
    doc = table.get(Query().device_id == device_id)

    if not doc:
        with click.Context(send_key_to_device) as ctx:
            click.echo(f"Keys for device {device_id} not present, please use: {ctx.command.name}")
            click.echo(get_attr_auth_keys.get_help(ctx))
            return

    shared_key = a2b_hex(doc["shared_key"].encode())
    fernet_key = Fernet(base64.urlsafe_b64encode(shared_key))

    keys = {
        "action:name": None,
        "device_type:description": None,
        "device:name": None,
        "device:status": None,
        "device_data:added": None,
        "device_data:num_data": None,
        "device_data:data": None,
        "scene:name": None,
        "scene:description": None
    }

    payload_keys = {}
    for k in keys:
        random_bytes = os.urandom(32)
        keys[k] = b2a_hex(random_bytes).decode()  # NOTE: retrieve key as `a2b_hex(key.encode())`
        payload_keys[k] = fernet_key.encrypt(random_bytes).decode()

    doc = {**doc, **keys}
    table.update(doc)

    client = _setup_client("user_id")  # TODO replace with actual user_id
    payload = _create_payload(1, payload_keys)
    ret = client.publish(f"1/{device_id}", payload)  # TODO replace with actual user_id
    click.echo(f"RC and MID = {ret}")


fake_tuple_data = None


@user.command()
@click.argument('device_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def get_device_data(device_id, token):
    """
    Queries server for data of :param device_id device and then verifies the received data using
    integrity information from device (received using MQTT Broker) and correctness hash attribute
    of each DB row.
    """
    user_id = 1  # TODO get it from env_var or file
    data = {"device_id": device_id, "access_token": token}

    r = requests.post(URL_GET_DEVICE_DATA, params=data, verify=VERIFY_CERTS)
    content = r.content.decode('unicode-escape')
    json_content = json_string_with_bytes_to_dict(content)

    _get_fake_tuple_data(user_id, int(device_id))
    fake_tuples, rows = _divide_fake_and_real_data(json_content["device_data"])
    verify_integrity_data(fake_tuple_data, fake_tuples)

    check_correctness_hash(rows, 'added', 'data', 'num_data')  # TODO add TID and update test and schema with correctness hashes that include TID
    click.echo(json_content["device_data"])
    click.echo(fake_tuple_data)


def _handle_on_message(mqtt_client, userdata, msg, device_id, user_id):
    msg.payload = bytes_to_json(msg.payload)  # TODO sanitize this?
    topic = msg.topic.split("/")
    if is_number(topic[0]) and int(topic[0]) == device_id and is_number(topic[1]) and int(topic[1]) == user_id:
        mqtt_client.disconnect()
        global fake_tuple_data
        fake_tuple_data = msg.payload


def _get_fake_tuple_data(user_id, device_id):
    payload_dict = {"request": "fake_tuple_info"}

    def on_message(mqtt_client, userdata, msg):
        _handle_on_message(mqtt_client, userdata, msg, device_id, user_id)

    client = _setup_client(str({user_id}))
    payload = _create_payload(user_id, payload_dict)
    client.subscribe(f"{device_id}/{user_id}")
    client.publish(f"{user_id}/{device_id}", payload)
    client.on_message = on_message
    click.echo("Waiting for response, CTRL-C to terminate...")
    client.loop_forever()


def _divide_fake_and_real_data(rows):
    """ Split data into 2 lists based on 'fakeness'
    Decrypts each row and computes fake correctness hash, then tests (using bcrypt)
    whether `correctness_hash` of row is 'same' as computed fake correctness hash """
    raise NotImplementedError


def get_encryption_keys(db_keys):
    """
    Retrieves encryption (decryption) keys corresponding to :param db_keys from TinyDB file
    :param db_keys: list of TinyDB key names, e.g.: ["device_type:description", "action:name"]
    :return: dictionary of key, value pair of column name and encryption string, e.g.: {"action:name": "9dd1a57836a5...858372a8c0c42515", ...}
    """
    raise NotImplementedError


def get_col_encryption_type(col_name):
    """
    Returns True or False based on whether the column is encrypted as number (OPE) or not (Fernet) - this
    is based on "is_numeric" attribute in TinyDB
    :param col_name: e.g. "device_data:data"
    :return:
    """
    raise NotImplementedError


def decrypt_row(row, keys):
    """
    :param row: example: {
        "added": -1000,
        "num_data": -1000,
        "data": 1000,
        "tid": 1
    }
    :param keys: example: {
        "added": [ "217b5c3430fd77e7a0191f04cbaf872be189d8cb203c54f7b083211e8e5f4f70", True],
        "num_data": [ "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d", True],
        "data": [ "d011b0fa5a23b3c2efadb2e0fea094647ff7b03b9a93022aeae6c1edf3eb1871", False]
    }
    """
    raise NotImplementedError


def is_fake(row):
    """
    Check whether row is fake tuple based on "correctness_hash" attribute in row and computed hash
    from other attributes in row.
    :param row: dict with keys as column names and values as values from server DB
    :return: bool, based on correctness hash check
    """
    raise NotImplementedError


def verify_integrity_data(fake_tuple_info, fake_rows):
    """
    Generates all fake tuples in <"lower_bound", "upper_bound"> range and verifies them againts :param fake_rows.
    :param fake_tuple_info: example: {
                    "added": {
                        "function_name": "triangle_wave",
                        "lower_bound": 5,
                        "upper_bound": 11,
                        "is_numeric": true
                    }
    :param fake_rows: list of dicts with keys as column names and values as values from server DB
    :return: False if any of the rows does not satisfy 'fakeness' check of if there less/more fake
    rows than there should be
    """
    raise NotImplementedError


def _setup_client(user_id):
    def on_publish(client, userdata, result):
        click.echo("Data published")

    client = paho.Client(user_id)
    client.on_publish = on_publish
    client.tls_set(ca_certs=os.path.join(os.path.dirname(__file__), "certs/server.crt"),
                   certfile=None,
                   keyfile=None,
                   tls_version=ssl.PROTOCOL_TLSv1_2)
    client.tls_insecure_set(True)
    client.connect(MQTT_BROKER, MQTT_PORT)
    return client


@user.command()
@click.argument('username')
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_set_api_username(username, token):
    data = {"api_username": username, "access_token": token}
    r = requests.post(AA_URL_SET_USERNAME, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def get_attr_auth_keys(token):
    data = {"access_token": token}
    r = requests.post(AA_URL_SETUP, params=data, verify=VERIFY_CERTS)
    content = json.loads(r.content.decode('unicode-escape'))
    click.echo(f"Saving keys to {path}")
    db = TinyDB(path)
    table = db.table(name='aa_keys')
    doc = table.get(where('public_key').exists() & where('master_key').exists())
    data = {"public_key": content["public_key"], "master_key": content["master_key"]}
    if doc:
        table.update(data)
    else:
        table.insert(data)


@user.command()
@click.argument('attr_list')
@click.argument('receiver_id')
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_keygen(attr_list, receiver_id, token):
    db = TinyDB(path)
    table = db.table(name='aa_keys')
    doc = table.get(where('public_key').exists() & where('master_key').exists())
    if not doc:
        with click.Context(get_attr_auth_keys) as ctx:
            click.echo(f"Master key not present, please use: {ctx.command.name}")
            click.echo(get_attr_auth_keys.get_help(ctx))
            return
    data = {
        "access_token": token,
        "master_key": doc['master_key'],
        "attr_list": re.sub('[\']', '', attr_list),
        "receiver_id": receiver_id
    }
    r = requests.post(AA_URL_KEYGEN, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('message')
@click.argument('policy_string')
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_encrypt(message, policy_string, token):
    data = {
        "access_token": token,
        "message": message,
        "policy_string": policy_string
    }
    r = requests.post(AA_URL_ENCRYPT, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('owner_username')
@click.argument('ciphertext')  # TODO allow specifying file path
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_decrypt(owner_username, ciphertext, token):
    data = {
        "access_token": token,
        "api_username": owner_username,
        "ciphertext": ciphertext
    }
    r = requests.post(AA_URL_DECRYPT, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


if __name__ == '__main__':
    # json_data = json.loads(create_device_type("test desc").content.decode("utf-8"))
    # print(json_data)
    # print(create_device(json_data["type_id"]).content.decode("utf-8"))
    # send_message()
    ...
