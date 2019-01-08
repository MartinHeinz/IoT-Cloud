import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from passlib.hash import bcrypt


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
