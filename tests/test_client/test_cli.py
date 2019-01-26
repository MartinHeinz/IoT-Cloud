import base64
import io
import os
import re
import tempfile
import warnings
from binascii import a2b_hex
from contextlib import redirect_stdout

import pytest
from cryptography.fernet import Fernet
from pyope.ope import OPE
from sqlalchemy.exc import SADeprecationWarning
from tinydb import TinyDB, where, Query

from app.app_setup import db, create_app
from app.cli import populate
import client.user.commands as cmd
import client.device.commands as device_cmd
from crypto_utils import hash, check_correctness_hash, instantiate_ope_cipher, int_from_bytes
from utils import json_string_with_bytes_to_dict

cmd.path = '/tmp/keystore.json'

# NOTE: These values are necessary here, because global vars are not properly initialized when using Click Test runner
cmd.VERIFY_CERTS = False
cmd.MQTT_BROKER = "172.21.0.3"
cmd.MQTT_PORT = 8883

device_cmd.path = '/tmp/data.json'


@pytest.fixture(scope="module", autouse=True)
def reset_attr_auth_db():
    """ Resets Dev DB before running CLI tests which have to be run against Dev Environment."""
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app(os.getenv('TESTING_ENV', "testing"))
    app.config["SQLALCHEMY_BINDS"]["attr_auth"] = app.config["SQLALCHEMY_BINDS"]["attr_auth"].replace("attr_auth_testing", "attr_auth")
    with app.app_context():
        with open(app.config["ATTR_AUTH_POPULATE_PATH"], 'r') as sql:
            db.get_engine(app, 'attr_auth').execute(sql.read())
        db.session.commit()
    app.config["SQLALCHEMY_BINDS"]["attr_auth"] = app.config["SQLALCHEMY_BINDS"]["attr_auth"].replace("attr_auth", "attr_auth_testing")


@pytest.fixture(scope="function")
def change_to_dev_db():
    """ Changes Default DB to `postgres` for CLI test."""
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app(os.getenv('TESTING_ENV', "testing"))
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_DATABASE_URI"].replace("testing", "postgres")
    ctx = app.app_context()
    ctx.push()
    yield app, ctx
    app.config["SQLALCHEMY_DATABASE_URI"] = re.sub(r"testing$", 'postgres', app.config["SQLALCHEMY_DATABASE_URI"])


def test_populate(runner):
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".sql") as tf:
        tf.write('''CREATE TABLE public.action (
                        id integer NOT NULL,
                        name character varying(200),
                        device_id integer
                      );''')
        tf.write("DROP TABLE public.action;")
        tf.flush()
        result = runner.invoke(populate, ["--path", tf.name, "--db", "testing", "--host", "localhost"], input="postgres")
    assert result.exit_code == 0


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_send_message(runner, access_token, reset_tiny_db):
    device_id = "23"
    key = "fcf064e7ea97ab828ba80578d255942e648c872d8d0c09a051bf5424640f2e68"
    result = runner.invoke(cmd.send_message, [device_id, "test"])
    assert f"Keys for device {device_id} not present, please use:" in result.output

    tiny_db = TinyDB(cmd.path)
    table = tiny_db.table(name='device_keys')
    table.insert({'device_id': device_id, 'shared_key': key})

    result = runner.invoke(cmd.send_message, [device_id, "test"])
    assert "Data published" in result.output
    assert "RC and MID = (0, 1)" in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_send_column_keys(runner, access_token, reset_tiny_db):
    device_id = "23"
    key = "fcf064e7ea97ab828ba80578d255942e648c872d8d0c09a051bf5424640f2e68"
    result = runner.invoke(cmd.send_column_keys, [device_id])
    assert f"Keys for device {device_id} not present, please use:" in result.output

    tiny_db = TinyDB(cmd.path)
    table = tiny_db.table(name='device_keys')
    table.insert({'device_id': device_id, 'shared_key': key})

    result = runner.invoke(cmd.send_column_keys, [device_id])
    assert "Data published" in result.output
    assert "RC and MID = (0, 1)" in result.output

    tiny_db = TinyDB(cmd.path)
    table = tiny_db.table(name='device_keys')
    doc = table.get(Query().device_id == device_id)
    assert "action:name" in doc
    assert len(doc) == 11
    shared_key = a2b_hex(doc["device:name"].encode())
    fernet_key = Fernet(base64.urlsafe_b64encode(shared_key))
    assert isinstance(fernet_key, Fernet)
    cipher = instantiate_ope_cipher(a2b_hex(doc["device_data:added"].encode()))
    assert isinstance(cipher, OPE)


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_parse_msg(runner, reset_tiny_db):
    data = """{"ciphertext": "gAAAAABcOiilUJ_u1tRSQ-iIghG4DgPOfCjUXOL2_FZ0f2XcPHcp5rDMu1dQMvFZ_4VlPr-QjG79HNes-F6bDxcr7K03R0r-8bWEZaFcS3j-ri0C-sy33Fc=", "user_id": 1}"""

    tiny_db = TinyDB(device_cmd.path)
    table = tiny_db.table(name='users')
    table.insert({"id": 1, "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc"})
    result = runner.invoke(device_cmd.parse_msg, [data])
    assert "{\"action\": true}" in result.output


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_save_column_keys(runner, reset_tiny_db):
    data = """{"device_data:data": "gAAAAABcRHiboBSiAuKLxvSqS1yu4vOR8FlqGBOnzJSQ85e5UShmQ9avtLAXx_w9fKad2xILHWbi_uFywJML8ukoDGB7iiHkLT39iOnrUCAQHFyOdFERixgl-iFHMji-S1YfGKGwxRIU", "device_data:num_data": "gAAAAABcRHibuWXtMvF7XgSN7FR-cHyNl2eDb_HHPCuTjqtdMN2VxxZnSxGCjkoJxRNIGMcpBW-z4n1wynPoCCb1VanmH3EukMPwpf7Vwk9WytkNR9h51ApyGt1QEkaj_JF2A5jKu-vw", "action:name": "gAAAAABcRHibSiR3cHtaSUSk1ipKP_7csl3xTCd4J-JesU8GPlC2iwfblksE3kvuV3U2mAYqiYe3UuYw04JPbYDYaFePY-YTUAzie3OCRzwuMTE6tE9UBJtJ8wUNJSctZnrvSi0rcPzQ", "device_type:description": "gAAAAABcRHibvjQEIYiaSi9yXLm2VPbgPsmye1mKv9DYF9ktCixOf6Cq03dKc1-ZpxucfrKJXOyT7vyq17cfxyrN9k-Bj4pi3BV7M68fLTR__03lK32W8LOLkMLWdMvxcURU1W8gg91f", "device:name": "gAAAAABcRHib0mxfmRE3mg4ALX3XPjP7ZuVQ69NiRdebiNCE-40wZuzzNV1krKcnZeRZVWXwYf4xjYLNNygY-kbbgxltBWNJ5rLanpBIqTeoq8uI9up1bZ_vFFCiGPIjHTpYkMnF5XIN", "device:status": "gAAAAABcRHiboBSiAuKLxvSqS1yu4vOR8FlqGBOnzJSQ85e5UShmQ9avtLAXx_w9fKad2xILHWbi_uFywJML8ukoDGB7iiHkLT39iOnrUCAQHFyOdFERixgl-iFHMji-S1YfGKGwxRIU", "device_data:added": "gAAAAABcRHibuWXtMvF7XgSN7FR-cHyNl2eDb_HHPCuTjqtdMN2VxxZnSxGCjkoJxRNIGMcpBW-z4n1wynPoCCb1VanmH3EukMPwpf7Vwk9WytkNR9h51ApyGt1QEkaj_JF2A5jKu-vw", "scene:name": "gAAAAABcRHibVgsVHRls8IGj95TdFKraKbGfyf_TvDzjg0KV_vu-HawiISBzRaxwrFV_QHI5jA73CTM2dF4ePENaMe0QtIJljtqCBUSRhoQideCy0JL4hDAIJUzpGXFK5RMC2fJHUJ17", "scene:description": "gAAAAABcRHib1iH0Bs9sHff-dt7FY9XOUDzARN-mwaq7eI7iLYYwtmBcMkB3T5ChNnoNWhIRLnh_lQLmvCT_itBvjoIHydBVdIcTjzsyHcTMBUdlxPmohokOjunxdMSCY0B48-pYqzsn", "user_id": 1}"""

    tiny_db = TinyDB(device_cmd.path)
    table = tiny_db.table(name='users')
    table.insert({"id": 1, "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc"})
    runner.invoke(device_cmd.save_column_keys, [data])

    tiny_db = TinyDB(device_cmd.path)
    table = tiny_db.table(name='users')
    doc = table.get(Query().id == 1)
    assert "action:name" in doc
    assert len(doc) == 11
    shared_key = a2b_hex(doc["device:status"].encode())
    fernet_key = Fernet(base64.urlsafe_b64encode(shared_key))
    assert isinstance(fernet_key, Fernet)
    cipher = instantiate_ope_cipher(a2b_hex(doc["device_data:added"].encode()))
    assert isinstance(cipher, OPE)


def test_create_device_type(runner, access_token):
    result = runner.invoke(cmd.create_device_type, ["description", '--token', access_token])
    assert "\"success\": true," in result.output
    assert "\"type_id\": " in result.output


def test_create_device(runner, access_token):
    result = runner.invoke(cmd.create_device_type, ["description-again", '--token', access_token])
    type_id = re.search('type_id": "(.+)"', result.output, re.IGNORECASE).group(1)
    result = runner.invoke(cmd.create_device, [type_id, "1", "CLITest", '--token', access_token])
    assert "\"success\": true" in result.output
    assert "\"id\": " in result.output


def test_get_device(runner, client, access_token):
    device_name = "my_raspberry"
    user_id = "1"
    device_name_bi = hash(device_name, user_id)

    result = runner.invoke(cmd.get_devices, [device_name, user_id, '--token', access_token])
    assert device_name_bi in result.output
    assert "failed correctness hash test!" not in result.output


def test_get_device_data_by_time_range(runner, client, access_token):
    result = runner.invoke(cmd.get_device_data_by_time_range, ['--token', access_token])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 4
    assert "failed correctness hash test!" not in result.output

    result = runner.invoke(cmd.get_device_data_by_time_range, ["--lower", 129952183, '--token', access_token])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 2
    assert "failed correctness hash test!" not in result.output

    result = runner.invoke(cmd.get_device_data_by_time_range, ["--lower", 129952183, "--upper", 262690267, '--token', access_token])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 1
    assert "failed correctness hash test!" not in result.output

    result = runner.invoke(cmd.get_device_data_by_time_range, ["--upper", 163081415, '--token', access_token])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 2
    assert "failed correctness hash test!" not in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_send_key_to_device(runner, access_token_two, reset_tiny_db):
    device_id = '45'
    device_id_2 = '34'

    result = runner.invoke(cmd.send_key_to_device, [device_id, '--token', access_token_two])
    assert "\"success\": true" in result.output
    result = runner.invoke(cmd.send_key_to_device, [device_id_2, '--token', access_token_two])
    assert "\"success\": true" in result.output

    db = TinyDB(cmd.path)
    table = db.table(name='device_keys')
    doc = table.search(where('device_id').exists() & where('public_key').exists() & where('private_key').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 2


def test_check_correctness_hash():
    query_result = [
        {
            "correctness_hash": "$2b$12$h15DOn5o9Lwb/dsgJMhSqew6s1skMN9PyLEGauBhZ6.DHiM4j88aW",
            "device_type_id": 23525,
            "id": 23,
            "name": "my_raspberry",
            "name_bi": "$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq",
            "owner_id": 1,
            "status": False
        }
    ]

    f = io.StringIO()
    with redirect_stdout(f):
        check_correctness_hash(query_result, "name")
    out = f.getvalue()

    assert "failed correctness hash test!" not in out

    query_result.append({
        "correctness_hash": '$2b$12$otw/RWY6QkCAuRjSptNY5.OstdUXC3GeVVk1y0vs4gBz86sw3haA.',
        "device_type_id": 23525,
        "id": 23,
        "name": "name1",
        "name_bi": "$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq",
        "owner_id": 1,
        "status": False
    })

    with redirect_stdout(f):
        check_correctness_hash(query_result, "name")
    out = f.getvalue()
    assert "failed correctness hash test!" in out


def test_aa_decrypt(runner, client, attr_auth_access_token_one, attr_auth_access_token_two):
    plaintext = "any text"

    result = runner.invoke(cmd.attr_auth_encrypt, [plaintext, "(GUESTTODAY)", '--token', attr_auth_access_token_one])
    assert "\"success\": true" in result.output
    ciphertext = re.search('\"ciphertext\": \"(.+)\"', result.output)
    assert ciphertext is not None
    ciphertext_string = ciphertext.group(1)

    result = runner.invoke(cmd.attr_auth_decrypt, ["MartinHeinz", ciphertext_string, '--token', attr_auth_access_token_two])
    assert "\"success\": true" in result.output
    assert plaintext in result.output


def test_aa_set_api_username(runner, attr_auth_access_token_one):
    result = runner.invoke(cmd.attr_auth_set_api_username, ["MartinHeinz", '--token', attr_auth_access_token_one])
    assert "\"success\": true" in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_aa_setup(runner, attr_auth_access_token_one, reset_tiny_db):
    result = runner.invoke(cmd.get_attr_auth_keys, ['--token', attr_auth_access_token_one])
    path = re.search('Saving keys to (.+\.json)', result.output)

    assert path is not None
    path_string = path.group(1)
    db = TinyDB(path_string)
    table = db.table(name='aa_keys')
    doc = table.search(where('public_key').exists() & where('master_key').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1, "More than one public and master key pair."


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_aa_keygen(runner, attr_auth_access_token_one, reset_tiny_db):
    result = runner.invoke(cmd.attr_auth_keygen, ["'TODAY GUEST'", '1', '--token', attr_auth_access_token_one])

    assert "Master key not present, please use: get-attr-auth-keys" in result.output
    runner.invoke(cmd.get_attr_auth_keys, ['--token', attr_auth_access_token_one])
    result = runner.invoke(cmd.attr_auth_keygen, ["'TODAY GUEST'", '1', '--token', attr_auth_access_token_one])
    assert "\"success\": true" in result.output


def test_aa_encrypt(runner, attr_auth_access_token_one):
    result = runner.invoke(cmd.attr_auth_encrypt, ["Hello World", "(GUESTTODAY)", '--token', attr_auth_access_token_one])
    assert "\"success\": true" in result.output
    assert "\"ciphertext\": " in result.output


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_device_init(runner, reset_tiny_db):
    runner.invoke(device_cmd.init, ["23"])
    tiny_db = TinyDB(device_cmd.path)
    table = tiny_db.table(name='device')
    doc = table.search(where('id').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1
    assert int(doc[0]['id']) == 23


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_device_receive_pk(runner, reset_tiny_db):
    data = "{'user_public_key': '-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8z5FnI9EoJZmxSXmKItAvZcdL/bjd4VM\nI2KCZU5gud4R034+VKfy0ameLSty3ImUzoOCClkXAvSBqIe+qKRuteGBeCrnVaIV\nWyk8DgOt4Y2Pp3W9Tm/5dRdxxl8RkCg7\n-----END PUBLIC KEY-----\n', 'user_id': '1'}"

    result = runner.invoke(device_cmd.receive_pk, [data])
    tiny_db = TinyDB(device_cmd.path)
    table = tiny_db.table(name='users')
    doc = table.search(where('id').exists() & where('shared_key').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1
    assert doc[0]['id'] == 1

    assert "\"user_id\": 1" in result.output
    assert "\"device_public_key\": \"-----BEGIN PUBLIC KEY-----" in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
@pytest.mark.parametrize('setup_user_device_public_key',
                         [(23,
                           1,
                           '-----BEGIN PUBLIC KEY-----\n'
                           'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2rD6Bhju8WSEFogdBxZt/N+n7ziUPi5C\n'
                           'QU1gSQQDNm57fdDuYNDOR7Wwb1fq5tSl2TC1D6WRTIt1gzzCsApGpZ3PIs7Wdbil\n'
                           'eJL/ETGa2Sqwav7JDH4r0V30sF4NqDok\n'
                           '-----END PUBLIC KEY-----\n',
                           'postgres'),
                          ], indirect=True)
def test_retrieve_device_public_key(runner, access_token, reset_tiny_db, setup_user_device_public_key):
    device_id = "23"
    result = runner.invoke(cmd.retrieve_device_public_key, [device_id, '--token', access_token])
    assert f"Keys for device {device_id} not present, please use:" in result.output

    tiny_db = TinyDB(cmd.path)
    table = tiny_db.table(name='device_keys')
    table.insert({
        "device_id": "99",
        "public_key": "anything",
        "private_key": "anything"
    })

    result = runner.invoke(cmd.retrieve_device_public_key, ["99", '--token', access_token])
    assert "\"success\": false" in result.output

    table.insert({
        "device_id": device_id,
        "public_key": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEP1oBLtMBa94A6IxKINUkIaOJRYShIsr+\nxu7H3ObkRljibL139knm8XXCTXG5jG/IIJvBdsDmTiHwPznZ0KRN9oIAc+CUqIeU\nUkEPQ87XAYqS2WTgg8vTPOml/htk3QbN\n-----END PUBLIC KEY-----\n",
        "private_key": "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDA9Nyrj4U915ZY6H//GY9o7WwchqnxqrUt8aIh64hfM9141yQa5qnTz\nTJCsZRcZSPSgBwYFK4EEACKhZANiAAQ/WgEu0wFr3gDojEog1SQho4lFhKEiyv7G\n7sfc5uRGWOJsvXf2SebxdcJNcbmMb8ggm8F2wOZOIfA/OdnQpE32ggBz4JSoh5RS\nQQ9DztcBipLZZOCDy9M86aX+G2TdBs0=\n-----END EC PRIVATE KEY-----\n"
    })

    runner.invoke(cmd.retrieve_device_public_key, [device_id, '--token', access_token])

    tiny_db = TinyDB(cmd.path)
    table = tiny_db.table(name='device_keys')
    doc = table.get(Query().device_id == device_id)
    assert "device_id" in doc and "shared_key" in doc
    assert "public_key" not in doc and "master_key" not in doc, "public_key and master_key should not be present anymore (Ephemeral keys need to be wiped)."


def test_dict_to_payload():
    kwargs = {
        "key1": "value",
        "key2": 1,
        "another": "test",
    }

    result = device_cmd.dict_to_payload(**kwargs)

    assert result == '{"key1": "value", "key2": 1, "another": "test"}'


def test_increment_upper_bounds():
    table = {
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
                "upper_bound": 25,
                "is_numeric": True
            },
            "data": {
                "function_name": "square_wave",
                "lower_bound": 1,
                "upper_bound": 43,
                "is_numeric": False
            },
        }
    }

    result = device_cmd.increment_bounds(table["device_data"])
    assert result["added"]["upper_bound"] == 2
    assert result["num_data"]["upper_bound"] == 26
    assert result["data"]["upper_bound"] == 44


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_get_fake_tuple(runner, reset_tiny_db):
    user_id = 1
    data = {"id": user_id,
            "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "action:name": "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d",
            "device_type:description": "2c567c6fde8d29ee3c1ac15e74692089fdce507a43eb931be792ec3887968d33",
            "device_data:added": "5b27b633b2ea8fd12617d36dc0e864b2e8c6e57e809662e88fe56d70d033429e",
            "device_data:num_data": "ed1b6067e3dec82b4b61360c29eaeb785987e0c36bfdba454b9eca2d1622ecc2",
            "device_data:data": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "scene:name": "7c2a6bb5e7021e30c7326bdb99003fd43b2b0770b0a4a07f7b3876634b11ff94",
            "scene:description": "d011b0fa5a23b3c2efadb2e0fea094647ff7b03b9a93022aeae6c1edf3eb1871"}

    tiny_db = TinyDB(device_cmd.path)
    table = tiny_db.table(name='users')
    table.insert(data)
    result = runner.invoke(device_cmd.get_fake_tuple, [str(user_id), "upper_bound"])
    tiny_db = TinyDB(device_cmd.path)
    table = tiny_db.table(name='users')
    doc = table.get(Query().id == user_id)
    assert "integrity" in doc, "Integrity sub-document wasn't inserted."
    assert all(val in doc["integrity"]["device_data"] for val in ["data", "num_data", "added"])

    search_res = re.findall('\"(tid|data|num_data|added|correctness_hash)\": \"?([^:,\"]+)\"?', result.output)

    assert len(search_res) == 5

    column, ciphertext = next(pair for pair in search_res if pair[0] == "data")
    key = a2b_hex(data[f"device_data:{column}"].encode())
    fernet_key = Fernet(base64.urlsafe_b64encode(key))
    plaintext = fernet_key.decrypt(ciphertext.encode())
    assert int_from_bytes(plaintext) == 1000

    result = runner.invoke(device_cmd.get_fake_tuple, [str(user_id), "upper_bound"])
    search_res = re.findall('\"(tid|data|num_data|added|correctness_hash)\": \"?([^:,\"]+)\"?', result.output)

    assert len(search_res) == 5

    column, ciphertext = next(pair for pair in search_res if pair[0] == "num_data")
    cipher = instantiate_ope_cipher(a2b_hex(data[f"device_data:{column}"].encode()))
    plaintext = cipher.decrypt(int(ciphertext))
    assert plaintext == -959

    tiny_db = TinyDB(device_cmd.path)
    table = tiny_db.table(name='users')
    doc = table.get(Query().id == user_id)
    assert doc["integrity"]["device_data"]["num_data"]["upper_bound"] == 2
    assert doc["integrity"]["device_data"]["added"]["upper_bound"] == 2
    assert doc["integrity"]["device_data"]["data"]["upper_bound"] == 2

    result = runner.invoke(device_cmd.get_fake_tuple, [str(user_id), "lower_bound"])
    search_res = re.findall('\"(tid|data|num_data|added|correctness_hash)\": \"?([^:,\"]+)\"?', result.output)

    assert len(search_res) == 5

    column, ciphertext = next(pair for pair in search_res if pair[0] == "num_data")
    cipher = instantiate_ope_cipher(a2b_hex(data[f"device_data:{column}"].encode()))
    plaintext = cipher.decrypt(int(ciphertext))
    assert plaintext == -980

    tiny_db = TinyDB(device_cmd.path)
    table = tiny_db.table(name='users')
    doc = table.get(Query().id == user_id)
    assert doc["integrity"]["device_data"]["num_data"]["lower_bound"] == 2
    assert doc["integrity"]["device_data"]["added"]["lower_bound"] == 2
    assert doc["integrity"]["device_data"]["data"]["lower_bound"] == 2
