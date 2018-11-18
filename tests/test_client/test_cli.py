import os
import re

from app.cli import populate
from client.user.commands import send_message, create_device, create_device_type
from tests.test_utils.fixtures import runner  # noqa


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


def test_populate(runner):
    result = runner.invoke(populate, ["--path", os.path.join(os.path.dirname(__file__), "..", "..", "app", "populate.sql")], input="postgres")
    assert result.exit_code == 0

