import io
import os
import re
import tempfile
from contextlib import redirect_stdout

from tinydb import TinyDB, where

from app.cli import populate
import client.user.commands as cmd
from crypto_utils import hash, check_correctness_hash
from utils import json_string_with_bytes_to_dict

cmd.path = '/tmp/keystore.json'


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
