from random import randint

import pytest
from pyope.ope import OPE

from client.crypto_utils import instantiate_ope_cipher


@pytest.fixture(scope="module", autouse=True)
def cipher():
    random_key = OPE.generate_key()
    c = instantiate_ope_cipher(random_key)
    return c


def test_ope_encrypt(benchmark, cipher):
    benchmark.pedantic(cipher.encrypt, args=(randint(0, 100000),), iterations=100, rounds=100)


def test_ope_decrypt(benchmark, cipher):
    benchmark.pedantic(cipher.decrypt, args=(cipher.encrypt(randint(0, 100000)),), iterations=100, rounds=100)
