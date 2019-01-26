import base64
import json
import os
import sys
from binascii import b2a_hex, a2b_hex

import click
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from tinydb import TinyDB, Query

try:  # for packaged CLI (setup.py)
    from client.crypto_utils import triangle_wave, sawtooth_wave, square_wave, sine_wave, generate, fake_tuple_to_hash, encrypt_fake_tuple
except ImportError:  # for un-packaged CLI
    from crypto_utils import triangle_wave, sawtooth_wave, square_wave, sine_wave, generate, fake_tuple_to_hash, encrypt_fake_tuple

dir_path = os.path.dirname(os.path.realpath(__file__))
path = f'{dir_path}/data.json'

GENERATING_FUNCTIONS = {
    "triangle_wave": triangle_wave,
    "sawtooth_wave": sawtooth_wave,
    "square_wave": square_wave,
    "sine_wave": sine_wave,
}


@click.group()
def device():
    pass


@device.command()
@click.argument('device_id')
def init(device_id):
    db = TinyDB(path)
    table = db.table(name='device')
    table.upsert({'id': device_id}, Query().id.exists())  # TODO change `device_id` to `int(device_id)`


@device.command()
@click.argument('data')
def parse_msg(data):
    """ Can be trigger by: `./cli.py -b "172.21.0.3" user send-message 23 "{\"action\": true}"` """
    try:  # TODO sanitize inputs; check for presence of shared key based on user
        data = json.loads(data)

        if "ciphertext" in data:
            db = TinyDB(path)
            table = db.table(name='users')
            doc = table.get(Query().id == data["user_id"])

            shared_key = a2b_hex(doc["shared_key"].encode())
            fernet_key = Fernet(base64.urlsafe_b64encode(shared_key))
            plaintext = fernet_key.decrypt(data["ciphertext"].encode())
            click.echo(plaintext)

    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


@device.command()
@click.argument('data')
def save_column_keys(data):
    """ Can be trigger by: `./cli.py -b "172.21.0.3" user send-column-keys 23` """
    try:
        data = json.loads(data)

        if "ciphertext" not in data:
            db = TinyDB(path)
            table = db.table(name='users')
            doc = table.get(Query().id == data["user_id"])
            data.pop("user_id", None)

            shared_key = a2b_hex(doc["shared_key"].encode())
            fernet_key = Fernet(base64.urlsafe_b64encode(shared_key))
            keys = {}
            for k, v in data.items():
                keys[k] = b2a_hex(fernet_key.decrypt(data[k].encode())).decode()

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

        db = TinyDB(path)
        table = db.table(name='users')
        key = b2a_hex(shared_key[:32]).decode()  # NOTE: retrieve key as `a2b_hex(key.encode())`
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
        db = TinyDB(path)
        table = db.table(name='users')
        doc = table.get(Query().id == int(user_id))
        if bound == "upper_bound":
            if "integrity" not in doc:  # If it doesn't exist create it with starting lower and upper bounds
                doc["integrity"] = init_integrity_data()
            else:  # If it does exist increment upper bounds
                doc["integrity"]["device_data"] = increment_bounds(doc["integrity"]["device_data"])

        cols = doc["integrity"]["device_data"]
        tid = max(cols[val][bound] for val in cols)
        fake_tuple = {**generate(doc["integrity"]["device_data"], bound=bound), "tid": tid}  # TODO make it work for whole tables not specific one

        keys = {}
        for t in doc["integrity"]:
            for col in doc["integrity"][t]:
                doc_key = f'{t}:{col}'
                keys[col] = [doc[doc_key], doc["integrity"][t][col]["is_numeric"]]

        encrypted_fake_tuple = encrypt_fake_tuple(fake_tuple, keys)
        fake_tuple_hash = fake_tuple_to_hash(encrypted_fake_tuple)

        row = {**encrypted_fake_tuple, "correctness_hash": fake_tuple_hash}

        if bound == "lower_bound":
            doc["integrity"]["device_data"] = increment_bounds(doc["integrity"]["device_data"], bound=bound)

        payload = dict_to_payload(**row)
        table.update(doc)
        click.echo(payload)

    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        line = exc_tb.tb_lineno
        click.echo(f"{repr(e)} at line: {line}")


def dict_to_payload(**kwargs):
    result = "{"
    for col, val in kwargs.items():
        if isinstance(val, int):
            result += f'"{col}": {val}, '
        else:
            result += f'"{col}": "{val}", '
    return result[:-2] + "}"


def init_integrity_data():
    return {
        "device_data": {
            "added": {
                "function_name": "triangle_wave",
                "lower_bound": 1,
                "upper_bound": 1,
                "is_numeric": True
            },
            "num_data": {
                "function_name": "sawtooth_wave",
                "lower_bound": 1,
                "upper_bound": 1,
                "is_numeric": True
            },
            "data": {
                "function_name": "square_wave",
                "lower_bound": 1,
                "upper_bound": 1,
                "is_numeric": False
            },
        }
    }


def increment_bounds(table, bound="upper_bound"):  # TODO check if lower_bound is smaller than upper_bound (can't remove what was not inserted yet)
    for k, v in table.items():
        table[k][bound] += 1
    return table
