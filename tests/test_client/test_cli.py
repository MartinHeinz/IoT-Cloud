import re
import tempfile

from app.cli import populate
from client.user.commands import send_message, create_device, create_device_type, get_devices, get_device_data_by_time_range
from crypto_utils import hash
from tests.test_utils.utils import json_string_with_bytes_to_dict


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
    result = runner.invoke(create_device_type, ["description"])
    assert "\"success\": true," in result.output
    assert "\"type_id\": " in result.output


def test_create_device(runner):
    result = runner.invoke(create_device_type, ["description-again"])
    type_id = re.search('type_id": "(.+)"', result.output, re.IGNORECASE).group(1)
    result = runner.invoke(create_device, [type_id])
    assert "\"success\": true" in result.output
    assert "\"id\": " in result.output


def test_get_device(runner, client):
    device_name = "my_raspberry"
    user_id = "1"
    device_name_bi = hash(device_name, user_id)

    result = runner.invoke(get_devices, [device_name, user_id])
    assert device_name_bi in result.output  # TODO sometimes fails with "AssertionError: assert '$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq' in ''"


def test_get_device_data_by_time_range(runner, client):

    result = runner.invoke(get_device_data_by_time_range)
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 4

    result = runner.invoke(get_device_data_by_time_range, ["--lower", 129952183])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 2

    result = runner.invoke(get_device_data_by_time_range, ["--lower", 129952183, "--upper", 262690267])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 1

    result = runner.invoke(get_device_data_by_time_range, ["--upper", 163081415])
    json_output = json_string_with_bytes_to_dict(result.output)
    assert len(json_output["device_data"]) == 2
