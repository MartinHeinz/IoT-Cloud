import io
import re
import tempfile
from contextlib import redirect_stdout

from app.cli import populate
from client.user.commands import send_message, create_device, create_device_type, get_devices, get_device_data_by_time_range
from crypto_utils import hash, check_correctness_hash
from utils import json_string_with_bytes_to_dict


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
    result = runner.invoke(send_message)
    assert "\"success\": true" in result.output


def test_create_device_type(runner):
    result = runner.invoke(create_device_type, ["description", '--token', "5c36ab84439c45a3719644c0d9bd7b31929afd9f"])
    assert "\"success\": true," in result.output
    assert "\"type_id\": " in result.output


def test_create_device(runner):
    result = runner.invoke(create_device_type, ["description-again", '--token', "5c36ab84439c45a3719644c0d9bd7b31929afd9f"])
    type_id = re.search('type_id": "(.+)"', result.output, re.IGNORECASE).group(1)
    result = runner.invoke(create_device, [type_id, "1", "CLITest", '--token', "5c36ab84439c45a3719644c0d9bd7b31929afd9f"])
    assert "\"success\": true" in result.output
    assert "\"id\": " in result.output


def test_get_device(runner, client):
    device_name = "my_raspberry"
    user_id = "1"
    device_name_bi = hash(device_name, user_id)

    result = runner.invoke(get_devices, [device_name, user_id, '--token', "5c36ab84439c45a3719644c0d9bd7b31929afd9f"])
    assert device_name_bi in result.output
    assert "failed correctness hash test!" not in result.output


def test_get_device_data_by_time_range(runner, client):

    result = runner.invoke(get_device_data_by_time_range, ['--token', "5c36ab84439c45a3719644c0d9bd7b31929afd9f"])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 4
    assert "failed correctness hash test!" not in result.output

    result = runner.invoke(get_device_data_by_time_range, ["--lower", 129952183, '--token', "5c36ab84439c45a3719644c0d9bd7b31929afd9f"])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 2
    assert "failed correctness hash test!" not in result.output

    result = runner.invoke(get_device_data_by_time_range, ["--lower", 129952183, "--upper", 262690267, '--token', "5c36ab84439c45a3719644c0d9bd7b31929afd9f"])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 1
    assert "failed correctness hash test!" not in result.output

    result = runner.invoke(get_device_data_by_time_range, ["--upper", 163081415, '--token', "5c36ab84439c45a3719644c0d9bd7b31929afd9f"])
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
