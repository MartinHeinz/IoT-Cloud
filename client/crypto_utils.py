import base64
import binascii
import hashlib
import hmac
import mmh3
import os
import sys
import zlib
from binascii import a2b_hex, b2a_hex

import click
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from passlib.hash import bcrypt
from pyope.ope import OPE, ValueRange
from scipy import signal
import numpy as np

sys.stdout = open(os.devnull, 'w')
sys.path.insert(0, '../app')
from app.attribute_authority.utils import create_pairing_group, create_cp_abe, deserialize_charm_object, serialize_charm_object

sys.stdout = sys.__stdout__


def encrypt(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = b'HQ\xd9\xb3Kz\n\xcc\xb224Q\xdb\xc7u\xb7'  # os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag


def decrypt(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


def blind_index(key, value):
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def correctness_hash(*strings):
    return bcrypt.using(rounds=12).hash(''.join(map(str, strings)))


def check_correctness_hash(query_result, *keys):
    for item in query_result:
        secret = "".join(str(item[key]) for key in keys)
        if not bcrypt.verify(secret, item["correctness_hash"]):
            click.echo(f"{item} failed correctness hash test!")


def derive_key(key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
        backend=default_backend()
    ).derive(key)


"""
To see the lists of values:
print(list(triangle_wave()))
print(list(sawtooth_wave()))
print(list(square_wave()))
print(list(sine_wave()))

To plot:
import matplotlib.pyplot as plt

t = np.linspace(0, 100, 500)
triangle = signal.sawtooth(10 * np.pi * 5 * t, 0.5)
plt.plot(t, triangle)
plt.show()
"""


def triangle_wave():
    t = np.linspace(0, 100, 500)
    triangle = signal.sawtooth(10 * np.pi * 5 * t, 0.5)
    yield from (int(round(x, 4)*1000) for x in triangle.tolist())


def sawtooth_wave():
    t = np.linspace(0, 100, 500)
    sawtooth = signal.sawtooth(10 * np.pi * 5 * t)
    yield from (int(round(x, 4)*1000) for x in sawtooth.tolist())


def square_wave():
    t = np.linspace(0, 100, 500)
    square = signal.square(8 * np.pi * 5 * t)
    yield from (int(round(x, 4)*1000) for x in square.tolist())


def sine_wave():
    t = np.linspace(0, 32 * np.pi, 500)
    sine = np.sin(t)
    yield from (int(round(x, 4)*1000) for x in sine.tolist())


def index_function():
    yield from range(1, 500)


def generate(columns, bound="upper_bound"):
    """
    :param bound: whether to use lower or upper bound
    :param columns: example
        {
         "added": {
            "seed": 3453657356745,
            "lower_bound": 1,
            "upper_bound": 1,
            "type": "OPE"
        , ...}
    :returns example: {
            "added": -1000,
            "num_data": -1000,
            "data": 1000,
        }
    """
    fake_tuple = {}
    for col, val in columns.items():
        if "seed" in val:
            fake_tuple[col] = murmur_hash(val[bound], val["seed"])
        else:
            fake_tuple[col] = val[bound]
    return fake_tuple


def encrypt_row(row, keys):
    """
    :param row: example: {
        "added": -1000,
        "num_data": -1000,
        "data": 1000,
        "tid": 1
    }
    :param keys: example: {
        "added": [ "217b5c3430fd77e7a0191f04cbaf872be189d8cb203c54f7b083211e8e5f4f70", "OPE"],
        "num_data": [ "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d", "OPE"],
        "data": [ "d011b0fa5a23b3c2efadb2e0fPUBLIC_KEY93022aeae6c1edf3eb1871", "ABE", "1-23 1-GUEST 1"]
    }
    """
    result = {}
    for col, val in row.items():
        if keys[col][1] == "Fernet":  # if key is for fernet, create Fernet token
            cipher = hex_to_fernet(keys[col][0])
            result[col] = cipher.encrypt(bytes(str(val), "utf-8")).decode()
        elif keys[col][1] == "OPE":  # if key is for OPE, create OPE cipher
            cipher = hex_to_ope(keys[col][0])
            result[col] = cipher.encrypt(val)
        else:  # if key is for ABE
            result[col] = encrypt_using_abe_serialized_key(keys[col][0], val, keys[col][2])
    return result


def murmur_hash(val, seed):
    return mmh3.hash(str(val), seed)


def get_random_seed(size=8):
    return int_from_bytes(os.urandom(size))


def instantiate_ope_cipher(key):
    return OPE(key, in_range=ValueRange(-100000000000, 100000000000), out_range=ValueRange(-214748364800, 214748364700))


def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big', signed=True)


def int_from_bytes(xbytes):
    return int.from_bytes(xbytes, 'big', signed=True)


def hex_to_key(h):
    return a2b_hex(h.encode())


def key_to_hex(k):
    return b2a_hex(k).decode()


def hex_to_fernet(h):
    k = hex_to_key(h)
    return Fernet(base64.urlsafe_b64encode(k))


def hex_to_ope(h):
    k = hex_to_key(h)
    return instantiate_ope_cipher(k)


def decrypt_using_fernet_hex(h, ciphertext):
    fernet_key = hex_to_fernet(h)
    plaintext = fernet_key.decrypt(ciphertext.encode())
    return plaintext


def encrypt_using_fernet_hex(h, plaintext):
    fernet_key = hex_to_fernet(h)
    ciphertext = fernet_key.encrypt(plaintext.encode())
    return ciphertext


def decrypt_using_ope_hex(h, ciphertext):
    cipher = hex_to_ope(h)
    plaintext = cipher.decrypt(int(ciphertext))
    return plaintext


def encrypt_using_abe_serialized_key(pk, plaintext, policy_string):
    pairing_group = create_pairing_group()  # TODO This is being imported from server app - might break with `setup.py`
    cp_abe = create_cp_abe()
    try:
        public_key = deserialize_charm_object(str.encode(pk), pairing_group)
    except binascii.Error:
        raise Exception("Invalid public key.")
    ciphertext = cp_abe.encrypt(public_key, str(plaintext), policy_string)
    return serialize_charm_object(ciphertext, pairing_group).decode("utf-8")


def decrypt_using_abe_serialized_key(serialized_ciphertext, serialized_pk, serialized_sk):
    pairing_group = create_pairing_group()
    cp_abe = create_cp_abe()
    try:
        public_key = deserialize_charm_object(str.encode(serialized_pk), pairing_group)
        private_key = deserialize_charm_object(str.encode(serialized_sk), pairing_group)
        ciphertext = deserialize_charm_object(str.encode(serialized_ciphertext), pairing_group)
    except (binascii.Error, zlib.error):
        raise Exception("One of the serialized objects is invalid.")
    plaintext = cp_abe.decrypt(public_key, private_key, ciphertext)

    return plaintext.decode("utf-8")


def pad_payload_attr(value):
    if len(value) > 256:
        raise Exception("Attribute value too long.")
    return value.ljust(256)


def unpad_payload_attr(value):
    if len(value) != 256:
        raise Exception("Attribute padded incorrectly.")
    return value.strip()


def unpad_row(attr_name, row):
    row[attr_name] = unpad_payload_attr(row[attr_name])
    return row
