import io
import os
import re
import tempfile
from contextlib import redirect_stdout

import pytest
from tinydb import TinyDB, where, Query

from app.app_setup import db
from app.cli import populate
import client.user.commands as cmd
import client.device.commands as device_cmd
from crypto_utils import hash, check_correctness_hash
from utils import json_string_with_bytes_to_dict

cmd.path = '/tmp/keystore.json'
cmd.VERIFY_CERTS = False

device_cmd.path = '/tmp/data.json'


@pytest.fixture(scope="module", autouse=True)
def reset_attr_auth_db(app_and_ctx):
    """ Resets Dev DB before running CLI tests which have to be run against Dev Environment."""
    app, ctx = app_and_ctx
    app.config["SQLALCHEMY_BINDS"]["attr_auth"] = app.config["SQLALCHEMY_BINDS"]["attr_auth"].replace("attr_auth_testing", "attr_auth")
    with app.app_context():
        with open(app.config["ATTR_AUTH_POPULATE_PATH"], 'r') as sql:
            db.get_engine(app, 'attr_auth').execute(sql.read())
        db.session.commit()
    app.config["SQLALCHEMY_BINDS"]["attr_auth"] = app.config["SQLALCHEMY_BINDS"]["attr_auth"].replace("attr_auth", "attr_auth_testing")


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


def test_send_message(runner):
    result = runner.invoke(cmd.send_message)
    assert "\"success\": true" in result.output


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


def test_send_key_to_device(runner, access_token_two):
    device_id = '45'
    device_id_2 = '34'
    if os.path.isfile(cmd.path):
        os.remove(cmd.path)

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


def test_aa_decrypt(runner, client, app_and_ctx, attr_auth_access_token_one, attr_auth_access_token_two):
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


def test_aa_setup(runner, attr_auth_access_token_one):
    if os.path.isfile(cmd.path):
        os.remove(cmd.path)

    result = runner.invoke(cmd.get_attr_auth_keys, ['--token', attr_auth_access_token_one])
    path = re.search('Saving keys to (.+\.json)', result.output)

    assert path is not None
    path_string = path.group(1)
    db = TinyDB(path_string)
    table = db.table(name='aa_keys')
    doc = table.search(where('public_key').exists() & where('master_key').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1, "More than one public and master key pair."

    os.remove(cmd.path)


def test_aa_keygen(runner, attr_auth_access_token_one):
    if os.path.isfile(cmd.path):
        os.remove(cmd.path)

    result = runner.invoke(cmd.attr_auth_keygen, ["'TODAY GUEST'", '1', '--token', attr_auth_access_token_one])

    assert "Master key not present, please use: get-attr-auth-keys" in result.output
    runner.invoke(cmd.get_attr_auth_keys, ['--token', attr_auth_access_token_one])
    result = runner.invoke(cmd.attr_auth_keygen, ["'TODAY GUEST'", '1', '--token', attr_auth_access_token_one])
    assert "\"success\": true" in result.output

    os.remove(cmd.path)


def test_aa_encrypt(runner, attr_auth_access_token_one):
    result = runner.invoke(cmd.attr_auth_encrypt, ["Hello World", "(GUESTTODAY)", '--token', attr_auth_access_token_one])
    assert "\"success\": true" in result.output
    assert "\"ciphertext\": " in result.output


def test_device_init(runner):
    if os.path.isfile(device_cmd.path):
        os.remove(device_cmd.path)

    runner.invoke(device_cmd.init, ["23"])
    db = TinyDB(device_cmd.path)
    table = db.table(name='device')
    doc = table.search(where('id').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1
    assert int(doc[0]['id']) == 23

    os.remove(device_cmd.path)


def test_device_receive_pk(runner):
    data = "{'user_public_key': '-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8z5FnI9EoJZmxSXmKItAvZcdL/bjd4VM\nI2KCZU5gud4R034+VKfy0ameLSty3ImUzoOCClkXAvSBqIe+qKRuteGBeCrnVaIV\nWyk8DgOt4Y2Pp3W9Tm/5dRdxxl8RkCg7\n-----END PUBLIC KEY-----\n', 'user_id': '1'}"

    if os.path.isfile(device_cmd.path):
        os.remove(device_cmd.path)

    result = runner.invoke(device_cmd.receive_pk, [data])
    db = TinyDB(device_cmd.path)
    table = db.table(name='users')
    doc = table.search(where('id').exists() & where('shared_key').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1
    assert doc[0]['id'] == 1

    assert "\"user_id\": 1" in result.output
    assert "\"device_public_key\": \"-----BEGIN PUBLIC KEY-----" in result.output

    os.remove(device_cmd.path)


def test_retrieve_device_public_key(runner, access_token):
    if os.path.isfile(device_cmd.path):
        os.remove(device_cmd.path)

    result = runner.invoke(cmd.retrieve_device_public_key, ["99", '--token', access_token])
    assert "\"success\": false" in result.output

    device_id = "23"
    result = runner.invoke(cmd.retrieve_device_public_key, [device_id, '--token', access_token])
    assert f"Keys for device {device_id} not present, please use:" in result.output

    db = TinyDB(cmd.path)
    table = db.table(name='device_keys')
    table.insert({
        "device_id": device_id,
        "public_key": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEP1oBLtMBa94A6IxKINUkIaOJRYShIsr+\nxu7H3ObkRljibL139knm8XXCTXG5jG/IIJvBdsDmTiHwPznZ0KRN9oIAc+CUqIeU\nUkEPQ87XAYqS2WTgg8vTPOml/htk3QbN\n-----END PUBLIC KEY-----\n",
        "private_key": "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDA9Nyrj4U915ZY6H//GY9o7WwchqnxqrUt8aIh64hfM9141yQa5qnTz\nTJCsZRcZSPSgBwYFK4EEACKhZANiAAQ/WgEu0wFr3gDojEog1SQho4lFhKEiyv7G\n7sfc5uRGWOJsvXf2SebxdcJNcbmMb8ggm8F2wOZOIfA/OdnQpE32ggBz4JSoh5RS\nQQ9DztcBipLZZOCDy9M86aX+G2TdBs0=\n-----END EC PRIVATE KEY-----\n"
    })
    runner.invoke(cmd.retrieve_device_public_key, [device_id, '--token', access_token])

    db = TinyDB(cmd.path)
    table = db.table(name='device_keys')
    doc = table.get(Query().device_id == device_id)
    assert "device_id" in doc and "shared_key" in doc
    assert "public_key" not in doc and "master_key" not in doc, "public_key and master_key should not be present anymore (Ephemeral keys need to be wiped)."
    os.remove(cmd.path)
