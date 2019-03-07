import json
import os
import sys
import time

import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from tinydb import Query
from tinydb.operations import decrement

sys.stdout = open(os.devnull, 'w')
sys.path.insert(0, '../app')
from app.utils import is_number

sys.stdout = sys.__stdout__

try:  # for packaged CLI (setup.py)
    from client.crypto_utils import triangle_wave, sawtooth_wave, square_wave, sine_wave, generate, encrypt_row, index_function, \
        hex_to_key, key_to_hex, hex_to_fernet, decrypt_using_fernet_hex, get_random_seed, blind_index, encrypt_using_abe_serialized_key, hex_to_ope, \
        correctness_hash, pad_payload_attr, encrypt_using_fernet_hex
    from client.utils import get_tinydb_table, search_tinydb_doc
except ImportError:  # pragma: no un-packaged CLI cover
    from crypto_utils import triangle_wave, sawtooth_wave, square_wave, sine_wave, generate, encrypt_row, index_function, \
        hex_to_key, key_to_hex, hex_to_fernet, decrypt_using_fernet_hex, get_random_seed, blind_index, \
        correctness_hash, pad_payload_attr, encrypt_using_fernet_hex
    from utils import get_tinydb_table, search_tinydb_doc

dir_path = os.path.dirname(os.path.realpath(__file__))
path = f'{dir_path}/data.json'


@click.group()
def device():
    pass


@device.command()
@click.argument('device_id')
@click.argument('password')
@click.argument('owner_id')
@click.argument('action_names', nargs=-1)
def init(device_id, password, owner_id, action_names):
    table = get_tinydb_table(path, 'device')
    table.upsert({'id': device_id, 'password': password, "owner_id": owner_id, "actions": action_names}, Query().id.exists())


@device.command()
@click.argument('data')
def parse_msg(data):
    """ Can be trigger by: `./cli.py -b "172.21.0.3" user send-message 23 "{\"action\": true}"` """
    try:  # TODO sanitize inputs; check for presence of shared key based on user
        data = json.loads(data)

        if "ciphertext" in data:
            doc = get_user_data()
            plaintext = decrypt_using_fernet_hex(doc["shared_key"], data["ciphertext"])
            click.echo(plaintext)

    except Exception as e:  # pragma: no exc cover
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


@device.command()
@click.argument('data')
def save_column_keys(data):
    """ Can be trigger by: `./cli.py -b "172.26.0.8" user send-column-keys 1 23` """
    try:
        data = json.loads(data)

        if "ciphertext" not in data:
            if get_owner_id() != int(data["user_id"]):
                click.echo("This command is only available for device owner.")
                return
            table = get_tinydb_table(path, 'users')
            doc = table.all()[0]
            data.pop("user_id", None)

            fernet_key = hex_to_fernet(doc["shared_key"])
            keys = {}
            for k, v in data.items():
                if k == "device_data:data":
                    keys[k] = json.loads(fernet_key.decrypt(data[k].encode()).decode())
                else:
                    keys[k] = key_to_hex(fernet_key.decrypt(data[k].encode()))

            doc = {**doc, **keys}
            table.update(doc)

    except Exception as e:  # pragma: no exc cover
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


@device.command()
@click.argument('data')
def receive_pk(data):
    try:
        json_data = json.loads(data.replace("'", '"'), strict=False)

        pk_user_pem = json.dumps(json_data['user_public_key'])
        user_id = int(json.dumps(json_data['user_id'])[1:-1])

        if get_owner_id() != user_id:
            click.echo("This command is only available for device owner.")
            return

        key = pk_user_pem[1:-1].encode('utf-8').replace(b"\\n", b"\n")
        public_key = load_pem_public_key(key, backend=default_backend())
        assert isinstance(public_key, EllipticCurvePublicKey)

        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        # derived_key = Fernet(base64.urlsafe_b64encode(shared_key[:32]))

        table = get_tinydb_table(path, 'users')
        key = key_to_hex(shared_key[:32])  # NOTE: retrieve key as `key_to_hex(key)`
        table.upsert({'id': user_id, 'shared_key': key, 'tid': -1}, Query().id == user_id)

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8').replace("\n", "\\n")
        payload = f'{{"user_id": {int(user_id)}, "device_public_key": "{public_pem}"}}'
        click.echo(payload)

    except Exception as e:  # pragma: no exc cover
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


@device.command()
@click.argument('bound')
def get_fake_tuple(bound):
    try:
        table = get_tinydb_table(path, 'users')
        doc = get_user_data()
        if bound == "upper_bound":
            if "integrity" not in doc:  # If it doesn't exist create it with starting lower and upper bounds
                doc["integrity"] = init_integrity_data()
            else:  # If it does exist increment upper bounds
                doc["integrity"]["device_data"] = increment_bounds(doc["integrity"]["device_data"])

        fake_tuple = {**generate(doc["integrity"]["device_data"], bound=bound)}
        fake_tuple["data"] = pad_payload_attr(str(fake_tuple["data"]))

        keys = get_key_type_pair(doc)

        fake_tuple_hash = correctness_hash([fake_tuple["added"], fake_tuple["data"], fake_tuple["num_data"], fake_tuple["tid"]])
        encrypted_fake_tuple = encrypt_row(fake_tuple, keys)
        row = {**encrypted_fake_tuple,
               "correctness_hash": fake_tuple_hash,
               "tid_bi": blind_index(hex_to_key(get_bi_key()), str(fake_tuple["tid"]))}

        if bound == "lower_bound":
            doc["integrity"]["device_data"] = increment_bounds(doc["integrity"]["device_data"], bound=bound)

        payload = dict_to_payload(**row)
        table.update(doc)
        click.echo(payload)

    except Exception as e:  # pragma: no exc cover
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


def get_self_id():
    table = get_tinydb_table(path, 'device')
    device_id = table.all()[0]["id"]
    return device_id


@device.command()
@click.argument('data')
def get_fake_tuple_info(data):
    try:
        data = json.loads(data)
        if "request" in data and data["request"] == "fake_tuple_info":
            doc = get_user_data()

            if "integrity" not in doc:
                raise Exception(f"Integrity data not initialized.")

            payload = encrypt_fake_tuple_info(doc)
            click.echo(payload)

    except Exception as e:  # pragma: no exc cover
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


def encrypt_fake_tuple_info(doc):
    payload = "{\"device_data\": \""
    data = "{"
    for k, v in doc["integrity"]["device_data"].items():
        data += f'"{k}": {dict_to_payload(**v)}, '
    data = data[:-2] + "}"
    payload += encrypt_using_fernet_hex(doc["shared_key"], data).decode()
    payload += " \"}"
    return payload


@device.command()
@click.argument('data')
def process_action(data):
    try:
        data = json.loads(data)
        if "action" in data:
            doc = get_user_data()

            action_name = decrypt_using_fernet_hex(doc["action:name"], data["action"])
            click.echo(action_name)

    except Exception as e:  # pragma: no exc cover
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


def broker_username_to_id(username):  # TODO not needed
    try:
        return username.split(":")[1]
    except IndexError:
        raise Exception(f"Invalid user ID: {username}")


@device.command()
@click.argument('user_id')
@click.argument('data')
@click.argument('num_data')
def save_data(user_id, data, num_data):
    try:
        if not is_number(num_data) or not is_number(user_id):
            return
        num_data = int(num_data)

        current_time_millis = int(round(time.time()))
        payload = dict_to_payload(**create_row(data, num_data, get_next_tid(), current_time_millis))
        click.echo(payload)

    except Exception as e:  # pragma: no exc cover
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


def create_row(data, num_data, tid, added):
    user_data = get_user_data()
    encrypted = encrypt_row({
        "added": added,
        "num_data": num_data,
        "data": data,
        "tid": str(tid)
    }, get_key_type_pair(user_data))
    encrypted["correctness_hash"] = correctness_hash(added, data, num_data, tid)
    encrypted["tid_bi"] = blind_index(hex_to_key(get_bi_key()), str(tid))

    return encrypted


def get_key_type_pair(user_data):
    keys = {}
    for t in user_data["integrity"]:
        for col in user_data["integrity"][t]:
            doc_key = f'{t}:{col}'
            if doc_key == "device_data:data":
                keys[col] = [user_data[doc_key]["public_key"],
                             user_data["integrity"][t][col]["type"],
                             user_data[doc_key]["policy"]]
            else:
                keys[col] = [user_data[doc_key], user_data["integrity"][t][col]["type"]]
    return keys


def get_next_tid():
    table = get_tinydb_table(path, 'users')
    tid = table.all()[0]["tid"]
    table.update(decrement('tid'))
    return tid


def get_user_data():
    table = get_tinydb_table(path, 'users')
    return table.all()[0]


def dict_to_payload(**kwargs):
    result = "{"
    for col, val in kwargs.items():
        if isinstance(val, bool):
            result += f'"{col}": {str(val).lower()}, '
        elif isinstance(val, int):
            result += f'"{col}": {val}, '
        else:
            result += f'"{col}": "{val}", '
    return result[:-2] + "}"


def init_integrity_data():
    return {
        "device_data": {
            "added": {
                "seed": get_random_seed(),
                "lower_bound": 1,
                "upper_bound": 1,
                "type": "OPE"
            },
            "num_data": {
                "seed": get_random_seed(),
                "lower_bound": 1,
                "upper_bound": 1,
                "type": "OPE"
            },
            "data": {
                "seed": get_random_seed(),
                "lower_bound": 1,
                "upper_bound": 1,
                "type": "ABE"
            },
            "tid": {
                "lower_bound": 1,
                "upper_bound": 1,
                "type": "Fernet"
            },
        }
    }


def increment_bounds(table, bound="upper_bound"):
    for k, v in table.items():
        if table[k]["lower_bound"] > table[k]["upper_bound"]:
            raise Exception("Invalid Bounds.")
        table[k][bound] += 1
    return table


def get_bi_key():
    table = get_tinydb_table(path, 'users')
    return table.all()[0]["bi_key"]


def get_owner_id():
    table = get_tinydb_table(path, 'device')
    return int(table.all()[0]["owner_id"])
