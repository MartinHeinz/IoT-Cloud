import base64
import mmh3
import os
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


def hash(value, salt):
    if salt == "":
        raise Exception("You need to specify salt (at least 1 character).")
    return bcrypt.using(rounds=12, salt=salt.ljust(22, "x")).hash(value)


def correctness_hash(*strings, fake=False):
    if not fake:
        return bcrypt.using(rounds=12).hash(''.join(map(str, strings)))
    return bcrypt.using(rounds=12).hash(''.join(map(str, strings)) + "1")
    # TODO bcrypt.using(rounds=12).hash(''.join(map(str, strings))) + "1" <- Based on paper it should be done like this


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
            "is_numeric": True
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


def encrypt_fake_tuple(fake_tuple, keys):
    """
    :param fake_tuple: example: {
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
    result = {}
    for col, val in fake_tuple.items():
        if not keys[col][1]:  # if key is for fernet (is_numeric is False) create Fernet token
            cipher = hex_to_fernet(keys[col][0])
            result[col] = cipher.encrypt(bytes(str(val), "utf-8")).decode()
        else:  # if key is for OPE (is_numeric is True) create OPE cipher
            cipher = hex_to_ope(keys[col][0])
            result[col] = cipher.encrypt(val)
    return result


def fake_tuple_to_hash(values):
    return correctness_hash(*values, fake=True)


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
