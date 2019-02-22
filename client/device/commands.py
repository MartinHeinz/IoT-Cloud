import json
import os
import sys

import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from tinydb import Query

try:  # for packaged CLI (setup.py)
    from client.crypto_utils import triangle_wave, sawtooth_wave, square_wave, sine_wave, generate, fake_tuple_to_hash, encrypt_fake_tuple, index_function, \
        hex_to_key, key_to_hex, hex_to_fernet, decrypt_using_fernet_hex, get_random_seed, blind_index
    from client.utils import get_tinydb_table, search_tinydb_doc
except ImportError:  # for un-packaged CLI
    from crypto_utils import triangle_wave, sawtooth_wave, square_wave, sine_wave, generate, fake_tuple_to_hash, encrypt_fake_tuple, index_function, \
        hex_to_key, key_to_hex, hex_to_fernet, decrypt_using_fernet_hex, get_random_seed
    from utils import get_tinydb_table, search_tinydb_doc

dir_path = os.path.dirname(os.path.realpath(__file__))
path = f'{dir_path}/data.json'


@click.group()
def device():
    pass


@device.command()
@click.argument('device_id')
@click.argument('password')
@click.argument('action_names', nargs=-1)
def init(device_id, password, action_names):
    table = get_tinydb_table(path, 'device')
    table.upsert({'id': device_id, 'password': password, "actions": action_names}, Query().id.exists())


@device.command()
@click.argument('data')
def parse_msg(data):
    """ Can be trigger by: `./cli.py -b "172.21.0.3" user send-message 23 "{\"action\": true}"` """
    try:  # TODO sanitize inputs; check for presence of shared key based on user
        data = json.loads(data)

        if "ciphertext" in data:
            doc = search_tinydb_doc(path, 'users', Query().id == data["user_id"])
            plaintext = decrypt_using_fernet_hex(doc["shared_key"], data["ciphertext"])
            click.echo(plaintext)

    except Exception as e:
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
            table = get_tinydb_table(path, 'users')
            doc = table.get(Query().id == data["user_id"])
            data.pop("user_id", None)

            fernet_key = hex_to_fernet(doc["shared_key"])
            keys = {}
            for k, v in data.items():
                if k == "device_data:data":
                    keys[k] = v
                else:
                    keys[k] = key_to_hex(fernet_key.decrypt(data[k].encode()))

            doc = {**doc, **keys}
            table.update(doc)

    except Exception as e:
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

        key = pk_user_pem[1:-1].encode('utf-8').replace(b"\\n", b"\n")
        public_key = load_pem_public_key(key, backend=default_backend())
        assert isinstance(public_key, EllipticCurvePublicKey)

        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        # derived_key = Fernet(base64.urlsafe_b64encode(shared_key[:32]))

        table = get_tinydb_table(path, 'users')
        key = key_to_hex(shared_key[:32])  # NOTE: retrieve key as `key_to_hex(key)`
        table.upsert({'id': user_id, 'shared_key': key}, Query().id == user_id)

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8').replace("\n", "\\n")
        payload = f'{{"user_id": {int(user_id)}, "device_public_key": "{public_pem}"}}'
        click.echo(payload)

    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


@device.command()
@click.argument('user_id')
@click.argument('bound')
def get_fake_tuple(user_id, bound):
    try:
        table = get_tinydb_table(path, 'users')
        doc = table.get(Query().id == int(user_id))
        if bound == "upper_bound":
            if "integrity" not in doc:  # If it doesn't exist create it with starting lower and upper bounds
                doc["integrity"] = init_integrity_data()
            else:  # If it does exist increment upper bounds
                doc["integrity"]["device_data"] = increment_bounds(doc["integrity"]["device_data"])

        fake_tuple = {**generate(doc["integrity"]["device_data"], bound=bound)}

        keys = {}
        for t in doc["integrity"]:
            for col in doc["integrity"][t]:
                doc_key = f'{t}:{col}'
                if doc_key == "device_data:data":
                    keys[col] = [doc[doc_key]["public_key"],
                                 doc["integrity"][t][col]["type"],
                                 " ".join(doc[doc_key]["attr_list"])]
                else:
                    keys[col] = [doc[doc_key], doc["integrity"][t][col]["type"]]

        fake_tuple_hash = fake_tuple_to_hash([fake_tuple["added"], fake_tuple["data"], fake_tuple["num_data"], fake_tuple["tid"]])
        encrypted_fake_tuple = encrypt_fake_tuple(fake_tuple, keys)
        row = {**encrypted_fake_tuple,
               "correctness_hash": fake_tuple_hash,
               "tid_bi": blind_index(hex_to_key(get_bi_key_by_user(int(user_id))), str(fake_tuple["tid"]))}

        if bound == "lower_bound":
            doc["integrity"]["device_data"] = increment_bounds(doc["integrity"]["device_data"], bound=bound)

        payload = dict_to_payload(**row)
        table.update(doc)
        click.echo(payload)

    except Exception as e:
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
            doc = search_tinydb_doc(path, 'users', Query().id == int(data["user_id"]))
            if doc is None:
                raise Exception(f"No user with ID {data['user_id']}")

            if "integrity" not in doc:
                raise Exception(f"Integrity data not initialized.")

            payload = "{\"device_data\": {"
            for k, v in doc["integrity"]["device_data"].items():
                payload += f'"{k}": {dict_to_payload(**v)}, '
            payload = payload[:-2] + "}}"  # TODO encrypt payload with shared_key?

            click.echo(payload)

    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


@device.command()
@click.argument('data')
def process_action(data):
    try:
        data = json.loads(data)
        if "action" in data:
            doc = search_tinydb_doc(path, 'users', Query().id == int(data["user_id"]))
            if doc is None:
                raise Exception(f"No user with ID {data['user_id']}")

            action_name = decrypt_using_fernet_hex(doc["action:name"], data["action"])
            click.echo(action_name)

    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


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


def get_bi_key_by_user(user_id):
    doc = search_tinydb_doc(path, 'users', Query().id == int(user_id))
    return doc["bi_key"]
