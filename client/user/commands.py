import copy
import json
import os
import re
import ssl
import sys
from json import JSONDecodeError

import click
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from paho.mqtt import client as paho
from tinydb import where, Query
from tinydb.operations import set

sys.stdout = open(os.devnull, 'w')
sys.path.insert(0, '../app')
from app.utils import bytes_to_json, is_number

sys.stdout = sys.__stdout__

try:  # for packaged CLI (setup.py)
    from client.crypto_utils import correctness_hash, check_correctness_hash, int_to_bytes, instantiate_ope_cipher, int_from_bytes, hex_to_key, \
        key_to_hex, hex_to_fernet, hex_to_ope, decrypt_using_fernet_hex, decrypt_using_ope_hex, encrypt_using_fernet_hex, murmur_hash, \
        decrypt_using_abe_serialized_key, blind_index, unpad_row, pad_payload_attr
    from client.utils import json_string_with_bytes_to_dict, _create_payload, search_tinydb_doc, get_tinydb_table, insert_into_tinydb, \
        get_shared_key_by_device_id
    from client.password_hashing import pbkdf2_hash
except ImportError:  # for un-packaged CLI
    from crypto_utils import correctness_hash, check_correctness_hash, instantiate_ope_cipher, int_from_bytes, hex_to_key, key_to_hex, \
        hex_to_fernet, hex_to_ope, decrypt_using_fernet_hex, decrypt_using_ope_hex, encrypt_using_fernet_hex, murmur_hash, \
        decrypt_using_abe_serialized_key, blind_index, unpad_row, pad_payload_attr
    from utils import json_string_with_bytes_to_dict, _create_payload, search_tinydb_doc, get_tinydb_table, insert_into_tinydb, \
        get_shared_key_by_device_id
    from password_hashing import pbkdf2_hash

URL_BASE = "https://localhost/api/"
URL_PUBLISH = URL_BASE + "publish"
URL_CREATE_DEVICE_TYPE = URL_BASE + "device_type/create"
URL_CREATE_DEVICE = URL_BASE + "device/create"
URL_CREATE_SCENE = URL_BASE + "scene/create"
URL_ADD_ACTION_TO_SCENE = URL_BASE + "scene/add_action"
URL_SET_ACTION = URL_BASE + "device/set_action"
URL_TRIGGER_ACTION = URL_BASE + "device/action"
URL_TRIGGER_SCENE = URL_BASE + "scene/trigger"
URL_AUTHORIZE_USER = URL_BASE + "device/authorize"
URL_REVOKE_USER = URL_BASE + "device/revoke"
URL_GET_DEVICE = URL_BASE + "device/get"
URL_GET_DEVICE_DATA_BY_RANGE = URL_BASE + "data/get_by_num_range"
URL_GET_DEVICE_DATA = URL_BASE + "data/get_device_data"
URL_START_KEY_EXCHANGE = URL_BASE + "exchange_session_keys"
URL_RECEIVE_PUBLIC_KEY = URL_BASE + "retrieve_public_key"
URL_REGISTER_TO_BROKER = URL_BASE + "user/broker_register"

AA_URL_BASE = "https://localhost/attr_auth/"
AA_URL_SET_USERNAME = AA_URL_BASE + "set_username"
AA_URL_SETUP = AA_URL_BASE + "setup"
AA_URL_KEYGEN = AA_URL_BASE + "user/keygen"
AA_URL_DEVICE_KEYGEN = AA_URL_BASE + "device/keygen"
AA_URL_SK_RETRIEVE = AA_URL_BASE + "user/retrieve_private_keys"
AA_URL_ENCRYPT = AA_URL_BASE + "encrypt"
AA_URL_DECRYPT = AA_URL_BASE + "decrypt"

dir_path = os.path.dirname(os.path.realpath(__file__))
path = f'{dir_path}/keystore.json'
fake_tuple_data = None


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
@click.argument('user_id')
@click.argument('device_id')
@click.argument('data')
def send_message(user_id, device_id, data):
    doc = search_tinydb_doc(path, 'device_keys', Query().device_id == device_id)

    if not doc:
        with click.Context(send_key_to_device) as ctx:
            click.echo(f"Keys for device {device_id} not present, please use: {ctx.command.name}")
            click.echo(send_key_to_device.get_help(ctx))
            return

    fernet_key = hex_to_fernet(doc["shared_key"])
    token = fernet_key.encrypt(data.encode())

    client = _setup_client(user_id)

    payload = f'"{json.dumps(_create_payload({"ciphertext": token.decode()}, user_id))}"'
    ret = client.publish(f"u:{user_id}/d:{device_id}/", payload)  # TODO change payload to json and parse it as JSON on device end
    click.echo(f"RC and MID = {ret}")


@user.command()
@click.argument('password')
@click.option('--token', envvar='ACCESS_TOKEN')
def register_to_broker(password, token):
    password_hash = pbkdf2_hash(password)
    data = {"password": password_hash, "access_token": token}
    r = requests.post(URL_REGISTER_TO_BROKER, params=data, verify=VERIFY_CERTS)
    content = json.loads(r.content.decode('unicode-escape'))
    table = get_tinydb_table(path, 'credentials')
    table.upsert({
        "broker_id": content["broker_id"],
        "broker_password": password
    }, Query().broker_id == content["broker_id"])


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
@click.argument('password')
@click.option('--token', envvar='ACCESS_TOKEN')
def create_device(device_type_id, device_name, password, token):
    password_hash = pbkdf2_hash(password)
    bi_key = os.urandom(32)
    device_name_key = key_to_hex(os.urandom(32))  # NOTE: retrieve key as `key_to_hex(key)`
    device_status_key = key_to_hex(os.urandom(32))
    data = {
        "type_id": device_type_id,
        "access_token": token,
        "name": hex_to_fernet(device_name_key).encrypt(device_name.encode()),
        "correctness_hash": correctness_hash(device_name),
        "name_bi": blind_index(bi_key, device_name),
        "password": password_hash
    }
    r = requests.post(URL_CREATE_DEVICE, params=data, verify=VERIFY_CERTS)
    content = json.loads(r.content.decode('unicode-escape'))
    if content["success"]:
        insert_into_tinydb(path, 'device_keys', {
            'device_id': str(content["id"]),
            'bi_key': key_to_hex(bi_key),
            'device:name': device_name_key,
            'device:status': device_status_key
        })
    click.echo(content)


@user.command()
@click.argument('name')
@click.argument('description')
@click.option('--token', envvar='ACCESS_TOKEN')
def create_scene(name, description, token):
    init_scene_keys()
    table = get_tinydb_table(path, 'scene_keys')
    doc = table.all()[0]
    name_ciphertext = encrypt_using_fernet_hex(doc["name"], name)
    desc_ciphertext = encrypt_using_fernet_hex(doc["description"], description)
    data = {
        "access_token": token,
        "name": name_ciphertext,
        "correctness_hash": correctness_hash(name),
        "name_bi": blind_index(get_global_bi_key(), name),
        "description": desc_ciphertext
    }
    r = requests.post(URL_CREATE_SCENE, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


def init_scene_keys():
    table = get_tinydb_table(path, 'global')
    table.upsert({
        'bi_key': key_to_hex(os.urandom(32)),
    }, where('bi_key').exists())

    table = get_tinydb_table(path, 'scene_keys')
    table.upsert({
        'name': key_to_hex(os.urandom(32)),
        'description': key_to_hex(os.urandom(32))
    }, where('name').exists() & where('description').exists())


@user.command()
@click.argument('scene_name')
@click.argument('action_name')
@click.argument('device_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def add_scene_action(scene_name, action_name, device_id, token):
    if not is_global_bi_key_missing(create_device, "Blind index key for scene name is missing"):
        data = {
            "access_token": token,
            "scene_name_bi": blind_index(get_global_bi_key(), scene_name),
            "action_name_bi": blind_index(get_device_bi_key(device_id), action_name),
        }
        r = requests.post(URL_ADD_ACTION_TO_SCENE, params=data, verify=VERIFY_CERTS)
        click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_id')
@click.argument('name')
@click.option('--token', envvar='ACCESS_TOKEN')
def set_action(device_id, name, token):
    doc = search_tinydb_doc(path, 'device_keys', Query().device_id == str(device_id))
    if not doc:
        with click.Context(send_key_to_device) as ctx:
            click.echo(f"Keys for device {device_id} not present, please use: {ctx.command.name}")
            click.echo(send_key_to_device.get_help(ctx))
            return

    data = {
        "device_id": device_id,
        "name": encrypt_using_fernet_hex(doc["action:name"], name),
        "correctness_hash": correctness_hash(name),
        "name_bi": blind_index(get_device_bi_key(device_id), name),
        "access_token": token
    }
    r = requests.post(URL_SET_ACTION, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_id')
@click.argument('name')
@click.option('--token', envvar='ACCESS_TOKEN')
def trigger_action(device_id, name, token):
    data = {
        "device_id": device_id,
        "name_bi": blind_index(get_device_bi_key(device_id), name),
        "access_token": token
    }
    r = requests.post(URL_TRIGGER_ACTION, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('name')
@click.option('--token', envvar='ACCESS_TOKEN')
def trigger_scene(name, token):
    data = {
        "name_bi": blind_index(get_global_bi_key(), name),
        "access_token": token
    }
    r = requests.post(URL_TRIGGER_SCENE, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_id')
@click.argument('auth_user_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def authorize_user(device_id, auth_user_id, token):
    data = {
        "device_id": device_id,
        "auth_user_id": auth_user_id,
        "access_token": token
    }
    r = requests.post(URL_AUTHORIZE_USER, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_id')
@click.argument('revoke_user_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def revoke_user(device_id, revoke_user_id, token):
    data = {
        "device_id": device_id,
        "revoke_user_id": revoke_user_id,
        "access_token": token
    }
    r = requests.post(URL_REVOKE_USER, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_name')
@click.argument('device_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def get_devices(device_name, device_id, token):
    device_name_bi = blind_index(get_device_bi_key(device_id), device_name)
    data = {"name_bi": device_name_bi, "access_token": token}
    r = requests.post(URL_GET_DEVICE, params=data, verify=VERIFY_CERTS)
    content = json.loads(r.content.decode('unicode-escape'))

    table = get_tinydb_table(path, 'device_keys')

    for device in content["devices"]:
        ciphertext = device["name"]
        doc = table.get(Query().device_id == str(device["id"]))
        plaintext = decrypt_using_fernet_hex(doc["device:name"], ciphertext)
        device["name"] = plaintext.decode()

    check_correctness_hash(content["devices"], "name")
    click.echo(content["devices"])


@user.command()
@click.argument('device_id')
@click.option('--lower', required=False)
@click.option('--upper', required=False)
@click.option('--token', envvar='ACCESS_TOKEN')
def get_device_data_by_num_range(device_id, lower=None, upper=None, token=""):
    user_id = 1
    if lower is not None and upper is not None:
        data = {"lower": int(lower), "upper": int(upper), "access_token": token, "device_id": device_id}
    elif lower is not None and upper is None:
        upper = 214748364700  # 100000000000
        data = {"lower": int(lower), "access_token": token, "device_id": device_id}
    elif lower is None and upper is not None:
        lower = -214748364800  # -100000000000
        data = {"upper": int(upper), "access_token": token, "device_id": device_id}
    else:
        lower = -214748364800  # -100000000000
        upper = 214748364700  # 100000000000
        data = {"lower": lower, "upper": upper, "access_token": token, "device_id": device_id}
    r = requests.post(URL_GET_DEVICE_DATA_BY_RANGE, params=data, verify=VERIFY_CERTS)
    content = r.content.decode('unicode-escape')
    json_content = json_string_with_bytes_to_dict(content)

    _get_fake_tuple_data(user_id, int(device_id))  # TODO decrypt fake_tuple_data
    decrypted_fake_tuple_data = {
        "device_data": json.loads(decrypt_using_fernet_hex(get_shared_key_by_device_id(path, device_id), fake_tuple_data["device_data"]).decode())}

    fake_tuples, rows = _divide_fake_and_real_data(json_content["device_data"], str(device_id), decrypted_fake_tuple_data)
    generated_tuples = generate_fake_tuples_in_range(decrypted_fake_tuple_data["device_data"])
    expected_fake_rows = slice_by_range(device_id, generated_tuples, int(lower), int(upper), "device_data:num_data")
    verify_integrity_data(expected_fake_rows, fake_tuples)

    if json_content["success"]:
        check_correctness_hash(rows, 'added', 'data', 'num_data', 'tid')

    result = []
    for row in rows:
        try:
            result.append(unpad_row("data", row))
        except Exception as e:
            click.echo(str(e))
    click.echo('{"device_data":' + str(result).replace("'", '"') + '}')


def slice_by_range(device_id, all_tuples, lower, upper, key_name):
    doc = search_tinydb_doc(path, 'device_keys', Query().device_id == str(device_id))
    plaintext_lower = decrypt_using_ope_hex(doc[key_name], lower)
    plaintext_upper = decrypt_using_ope_hex(doc[key_name], upper)
    result = []
    for row in all_tuples:
        if plaintext_lower <= row[key_name.split(":")[1]] <= plaintext_upper:
            result.append(row)

    return result


@user.command()
@click.argument('device_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def send_key_to_device(device_id, token):
    if not is_device_bi_key_missing(device_id, create_device, "Blind index key for device name is missing"):
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
        table = get_tinydb_table(path, 'device_keys')
        table.upsert({
            'device_id': device_id,
            'public_key': public_pem,
            'private_key': private_pem,
            'key_bi': key_to_hex(get_device_bi_key(device_id))
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

    table = get_tinydb_table(path, 'device_keys')
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

    key = key_to_hex(shared_key[:32])  # NOTE: retrieve key as `key_to_hex(key)`
    table.remove(Query().device_id == device_id)
    table.insert({'device_id': device_id, 'shared_key': key})


@user.command()
@click.argument('user_id')
@click.argument('device_id')
def send_column_keys(user_id, device_id):
    table = get_tinydb_table(path, 'device_keys')
    doc = table.get(Query().device_id == device_id)

    if not doc:
        with click.Context(send_key_to_device) as ctx:
            click.echo(f"Keys for device {device_id} not present, please use: {ctx.command.name}")
            click.echo(get_attr_auth_keys.get_help(ctx))
            return

    fernet_key = hex_to_fernet(doc["shared_key"])

    keys = {
        "action:name": None,
        "device_type:description": None,  # TODO remove this
        "device_data:added": None,
        "device_data:num_data": None,
        "device_data:tid": None
    }

    payload_keys = {}
    for k in keys:
        random_bytes = os.urandom(32)
        keys[k] = key_to_hex(random_bytes)  # NOTE: retrieve key as `key_to_hex(key)`
        payload_keys[k] = fernet_key.encrypt(random_bytes).decode()

    payload_keys["device_data:data"] = doc["device_data:data"]
    payload_keys["device:name"] = doc["device:name"]
    payload_keys["device:status"] = doc["device:status"]
    bi_key = get_global_bi_key()
    payload_keys["bi_key"] = fernet_key.encrypt(bi_key).decode()
    keys["bi_key"] = key_to_hex(bi_key)

    doc = {**doc, **keys}
    table.upsert(doc, Query().device_id == device_id)

    client = _setup_client(user_id)
    payload = f'"{json.dumps(_create_payload(payload_keys, user_id))}"'
    ret = client.publish(f"u:{user_id}/d:{device_id}/", payload)
    click.echo(f"RC and MID = {ret}")


@user.command()
@click.argument('attr_list')
@click.argument('device_id')
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_device_keygen(attr_list, device_id, token):
    if device_id not in attr_list:
        click.echo(f"attr_list argument should contain device_id ({device_id})")
        return
    doc = search_tinydb_doc(path, 'aa_keys', where('public_key').exists())
    if not doc:
        with click.Context(get_attr_auth_keys) as ctx:
            click.echo(f"Public key not present, please use: {ctx.command.name}")
            click.echo(get_attr_auth_keys.get_help(ctx))
            return

    attr_list = re.sub('[\']', '', attr_list)
    data = {
        "access_token": token,
        "attr_list": attr_list
    }
    r = requests.post(AA_URL_DEVICE_KEYGEN, params=data, verify=VERIFY_CERTS)
    content = r.content.decode('unicode-escape')
    json_content = json_string_with_bytes_to_dict(content)

    t = get_tinydb_table(path, "device_keys")
    device_data_doc = {
        "private_key": json_content["private_key"],
        "attr_list": attr_list.split(),
    }
    t.update(set("device_data:data", device_data_doc), Query().device_id == device_id)


@user.command()
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_retrieve_private_keys(token):
    data = {"access_token": token}
    r = requests.post(AA_URL_SK_RETRIEVE, params=data, verify=VERIFY_CERTS)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('user_id')
@click.argument('device_id')
@click.argument('device_name')
@click.option('--token', envvar='ACCESS_TOKEN')
def get_device_data(user_id, device_id, device_name, token):  # TODO right now it requires device to 1st use `get_fake_tuple` (`init_integrity_data`) before 1st call to this
    """
    Queries server for data of :param device_id device and then verifies the received data using
    integrity information from device (received using MQTT Broker) and correctness hash attribute
    of each DB row.
    """
    user_id = int(user_id)
    device_name_bi = blind_index(get_device_bi_key(device_id), device_name)
    data = {"device_name_bi": device_name_bi, "access_token": token}

    r = requests.post(URL_GET_DEVICE_DATA, params=data, verify=VERIFY_CERTS)
    content = r.content.decode('unicode-escape')
    json_content = json_string_with_bytes_to_dict(content)

    _get_fake_tuple_data(user_id, int(device_id))
    decrypted_fake_tuple_data = {
        "device_data": json.loads(decrypt_using_fernet_hex(get_shared_key_by_device_id(path, device_id), fake_tuple_data["device_data"]).decode())}

    fake_tuples, rows = _divide_fake_and_real_data(json_content["device_data"], device_id, decrypted_fake_tuple_data)

    verify_integrity_data(generate_fake_tuples_in_range(decrypted_fake_tuple_data["device_data"]), fake_tuples)
    check_correctness_hash(rows, 'added', 'data', 'num_data', 'tid')

    result = []
    for row in rows:
        try:
            result.append(unpad_row("data", row))
        except Exception as e:
            click.echo(str(e))
    click.echo(result)


def _handle_on_message(mqtt_client, userdata, msg, device_id, user_id):
    try:
        msg.payload = bytes_to_json(msg.payload)
    except JSONDecodeError:
        click.echo(f"Received invalid payload: {msg.payload.decode()}")
        return
    topic = msg.topic.split("/")
    t_sender, sender_id = topic[0].split(":")
    t_receiver, receiver_id = topic[1].split(":")
    if t_sender == "d" and t_receiver == "u":
        if is_number(sender_id) and int(sender_id) == device_id and is_number(receiver_id) and int(receiver_id) == user_id:
            mqtt_client.disconnect()
            global fake_tuple_data
            fake_tuple_data = msg.payload
        return
    click.echo(f"Received invalid topic: {msg.topic}")


def _get_fake_tuple_data(user_id, device_id):
    payload_dict = {"request": "fake_tuple_info"}

    def on_message(mqtt_client, userdata, msg):
        _handle_on_message(mqtt_client, userdata, msg, device_id, user_id)

    client = _setup_client(str({user_id}))
    payload = f'"{json.dumps(_create_payload(payload_dict, user_id))}"'
    sub_topic = f"d:{device_id}/u:{user_id}/"
    client.subscribe(sub_topic)
    client.publish(f"u:{user_id}/d:{device_id}/", payload)
    client.on_message = on_message
    click.echo(f"Subscribed to {sub_topic}")
    click.echo("Waiting for response, CTRL-C to terminate...")
    client.loop_forever()


def _divide_fake_and_real_data(rows, device_id, integrity_info):
    """ Split data into 2 lists based on 'fakeness'
    Decrypts each row and computes fake correctness hash, then tests (using bcrypt)
    whether `correctness_hash` of row is 'same' as computed fake correctness hash
    :param device_id
    :param rows: example: [{
        'added': 37123,
        'correctness_hash': '$2b$12$FSuBaNwezizWJcj47RxYJOpur2k49IJObfIPLDce5pKpRRZEASt6m',
        'data': 'gAAAAABcUECMQMM0MjKknugGdI6YN81pLtmLUrcMsjHMBG87KpIJFWZF8n1DTVJX7VvnlVMMN4BNGdVROLeCD_I0XUs0IAK9AA==',
        'device_id': 23,
        'id': 1,
        'num_data': -9199,
        'tid': 3}, ...]
    """
    db_col_names = ["device_data:added", "device_data:data", "device_data:tid", "device_data:num_data"]
    enc_keys = get_encryption_keys(device_id, db_col_names)
    col_types = {col: get_col_encryption_type(col, integrity_info) for col in db_col_names}
    key_type_pairs = {}
    for k, v in enc_keys.items():
        if ":" in k:
            if k == "device_data:data":
                key_type_pairs[k.split(":")[1]] = [enc_keys[k][0], col_types[k], enc_keys[k][1]]  # public, type, private
            else:
                key_type_pairs[k.split(":")[1]] = [enc_keys[k], col_types[k]]  # private, type

    real, fake = [], []
    for row in rows:
        modified = row
        modified.pop("id")
        modified.pop("device_id")
        modified.pop("tid_bi")
        row_correctness_hash = modified.pop("correctness_hash")
        decrypted = decrypt_row(modified, key_type_pairs)
        if is_fake(decrypted):
            decrypted["correctness_hash"] = row_correctness_hash
            fake.append(decrypted)
        else:
            decrypted["correctness_hash"] = row_correctness_hash
            real.append(decrypted)

    return fake, real


def get_encryption_keys(device_id, db_keys):
    """
    Retrieves encryption (decryption) keys corresponding to :param db_keys from TinyDB file
    :param device_id
    :param db_keys: list of TinyDB key names, e.g.: ["device_type:description", "action:name"]
    :return: dictionary of key, value pair of column name and encryption string, e.g.: {"action:name": "9dd1a57836a5...858372a8c0c42515", ...}
    """
    doc = search_tinydb_doc(path, 'device_keys', Query().device_id == str(device_id))
    result = {}
    for key in db_keys:
        if ":" in key:
            if key == "device_data:data":
                result[key] = [doc[key]["public_key"], doc[key]["private_key"]]
            else:
                result[key] = doc[key]
    return result


def get_col_encryption_type(col_name, integrity_info):
    """
    Returns type based on whether the column is encrypted as number (OPE) or symmetrically (Fernet) or asymmetrically (ABE)- this
    is based on "type" attribute in TinyDB
    :param integrity_info: {
            'device_data': {
                'added': {
                    'seed': 12312412,
                    'lower_bound': 1,
                    'upper_bound': 1,
                    'type': "OPE"
                    }}}
    :param col_name: e.g. "device_data:data"
    :return:
    """
    table, col = col_name.split(":")
    return integrity_info[table][col]["type"]


def decrypt_row(row, keys):
    """
    :param row: example: {
        "added": 36976,
        "num_data": -9272,
        "data": "gAAAAABcTyUFZrhQRLzLvwep7j0Vm2UFjS2ylZ7bjB2YRueDpX15tobA0oOSEWBYZ4LaCKRa_h7WyKMacAAt-982srPPOR_1Cw==",
        "tid": 1
    }
    :param keys: example:
        "added": ["26751017213ff85f189bedc34d302acfdf1649d5e1bac653a9709171ad37b155", "OPE"],
        "num_data": ["84964a963c097c550b41a085bbf1ad93ba5a1046aa5495d86d62f9623ab89cc6", "OPE"],
        "data": ["1fac0f8fa2083fe32c21d0PUBLIC_KEYf6959afb9f44623048e6875", "ABE", "rgesdrgPRIVATE_KEYedhder"]
    }
    """
    result = {}
    for col, val in row.items():
        if keys[col][1] == "Fernet":  # if key is for fernet, create Fernet token
            result[col] = decrypt_using_fernet_hex(keys[col][0], val).decode()
        elif keys[col][1] == "OPE":  # if key is for OPE, create OPE cipher
            result[col] = decrypt_using_ope_hex(keys[col][0], val)
        else:
            result[col] = decrypt_using_abe_serialized_key(val, keys[col][0], keys[col][2])
    return result


def is_fake(row_values):
    """
    Check whether row is fake tuple based on "tid" attribute in row and computed hash
    from other attributes in row.
    :param row_values: dict with keys as column names and values as values from server DB (decrypted using `decrypt_row`)
    :return: bool
    """
    return int(row_values["tid"]) > 0  # Positive numbers are fake


def verify_integrity_data(expected_tuples, present_rows):
    """
    :param expected_tuples: list of dicts with keys as column names and values as values from server DB
        (generated fake tuples, that should be present in DB)
    :param present_rows: list of dicts with keys as column names and values as values from server DB
        (queried tuples)
    :return: False if any of the rows does not satisfy 'fakeness' check of if there less/more fake
    rows than there should be
    """
    modified = copy.deepcopy(present_rows)
    for i, row in enumerate(modified):
        modified[i].pop("correctness_hash")

    if expected_tuples == modified:
        click.echo("Data Integrity satisfied.")
    else:
        click.echo("Data Integrity NOT satisfied.")


def generate_fake_tuples_in_range(fake_tuple_info):
    """
    Generates all fake tuples in <"lower_bound", "upper_bound"> range and verifies them againts :param fake_rows.
    :param fake_tuple_info: example: {
                    "added": {
                        "seed": 4574675,
                        "lower_bound": 5,
                        "upper_bound": 11,
                        "is_numeric": True
                    }
    :return: list of dicts (each dict contains single tuple with keys as column names and values)
    """
    fake_tuple_col_values = {}
    fake_tuples = []
    lb, ub = 0, 0
    for col, val in fake_tuple_info.items():
        lb = fake_tuple_info[col]["lower_bound"]
        ub = fake_tuple_info[col]["upper_bound"] + 1
        if "seed" in fake_tuple_info[col]:
            fake_tuple_col_values[col] = [murmur_hash(str(i), fake_tuple_info[col]["seed"]) for i in range(lb, ub)]
        else:
            fake_tuple_col_values[col] = list(range(lb, ub))
    for no, i in enumerate(range(lb, ub)):
        fake_tuples.append({"added": fake_tuple_col_values["added"][no],
                            "num_data": fake_tuple_col_values["num_data"][no],
                            "data": pad_payload_attr(str(fake_tuple_col_values["data"][no])),
                            "tid": str(fake_tuple_col_values["tid"][no])})
    return fake_tuples


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
    doc = search_tinydb_doc(path, 'credentials', where('broker_id').exists() & where('broker_password').exists())
    client.username_pw_set(doc['broker_id'], doc['broker_password'])
    client.connect(MQTT_BROKER, MQTT_PORT, 30)
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
    table = get_tinydb_table(path, 'aa_keys')
    doc = table.get(where('public_key').exists())
    data = {"public_key": content["public_key"]}
    if doc:
        table.update(data)
    else:
        table.insert(data)


@user.command()
@click.argument('attr_list')
@click.argument('receiver_id')
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_keygen(attr_list, receiver_id, token):
    doc = search_tinydb_doc(path, 'aa_keys', where('public_key').exists())
    if not doc:
        with click.Context(get_attr_auth_keys) as ctx:
            click.echo(f"Public key not present, please use: {ctx.command.name}")
            click.echo(get_attr_auth_keys.get_help(ctx))
            return
    data = {
        "access_token": token,
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


def is_global_bi_key_missing(command, message):
    doc = search_tinydb_doc(path, 'global', Query().bi_key.exists())
    if not doc:
        with click.Context(command) as ctx:
            click.echo(f"{message}, please use: {ctx.command.name}")
            click.echo(command.get_help(ctx))
            return True
    return False


def get_global_bi_key():
    table = get_tinydb_table(path, 'global')
    doc_global = table.all()[0]
    return hex_to_key(doc_global["bi_key"])


def get_device_bi_key(device_id):
    doc = search_tinydb_doc(path, 'device_keys', Query().device_id == str(device_id))
    return hex_to_key(doc["bi_key"])


def is_device_bi_key_missing(device_id, command, message):
    doc = search_tinydb_doc(path, 'device_keys', Query().device_id == str(device_id))
    if doc is None or "bi_key" not in doc:
        with click.Context(command) as ctx:
            click.echo(f"{message}, please use: {ctx.command.name}")
            click.echo(command.get_help(ctx))
            return True
    return False


if __name__ == '__main__':
    # json_data = json.loads(create_device_type("test desc").content.decode("utf-8"))
    # print(json_data)
    # print(create_device(json_data["type_id"]).content.decode("utf-8"))
    # send_message()
    ...
