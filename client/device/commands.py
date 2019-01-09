import base64
import json
import os
from binascii import b2a_hex

import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from tinydb import TinyDB, Query

from crypto_utils import decrypt


dir_path = os.path.dirname(os.path.realpath(__file__))
path = f'{dir_path}/data.json'


@click.group()
def device():
    pass


@device.command()
@click.argument('device_id')
def init(device_id):
    db = TinyDB(path)
    table = db.table(name='device')
    table.upsert({'id': device_id}, Query().id.exists())


@device.command()
@click.argument('ciphertext')
@click.argument('tag')
def parse_msg(ciphertext, tag):
    try:
        ciphertext_decoded = base64.b64decode(ciphertext)
        tag_decoded = base64.b64decode(tag)

        key = b'f\x9c\xeb Lj\x13n\x84B\xf5S\xb5\xdfnl53d\x10\x12\x92\x82\xe1\xe3~\xc8*\x16\x9f\xd69'  # os.urandom(32)
        iv = b'HQ\xd9\xb3Kz\n\xcc\xb224Q\xdb\xc7u\xb7'  # os.urandom(16)

        data = decrypt(
            key,
            b"authenticated but not encrypted payload",
            iv,
            ciphertext_decoded,
            tag_decoded
        )
        click.echo(data.decode("utf-8"))
    except:
        click.echo("Incorrect payload.")


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
        click.echo(str(e))
