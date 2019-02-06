import io
import os
import re
import subprocess
import tempfile
import warnings
from contextlib import redirect_stdout
from unittest import mock
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet
from paho.mqtt.client import MQTTMessage
from pyope.ope import OPE
from sqlalchemy.exc import SADeprecationWarning
from tinydb import where, Query

from app.app_setup import db, create_app
from app.cli import populate
import client.user.commands as cmd
import client.device.commands as device_cmd
from app.models.models import MQTTUser, User
from crypto_utils import hash, check_correctness_hash, hex_to_fernet, hex_to_ope, decrypt_using_fernet_hex, \
    decrypt_using_ope_hex
from utils import json_string_with_bytes_to_dict, get_tinydb_table, search_tinydb_doc, insert_into_tinydb

cmd.path = '/tmp/keystore.json'

# NOTE: These values are necessary here, because global vars are not properly initialized when using Click Test runner
cmd.VERIFY_CERTS = False
cmd.MQTT_BROKER = "172.22.0.3"
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
    app.config["SQLALCHEMY_DATABASE_URI"] = re.sub(r"postgres$", 'testing', app.config["SQLALCHEMY_DATABASE_URI"])


def test_populate(runner):
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".sql") as tf:
        tf.write('''CREATE TABLE public.action (
                        id integer NOT NULL,
                        name character varying(200),
                        device_id integer
                      );''')
        tf.write("DROP TABLE public.action;")
        tf.flush()
        ip = subprocess.Popen("hostname -I | cut -d' ' -f1", shell=True, stdout=subprocess.PIPE).stdout.read().strip().decode()
        result = runner.invoke(populate, ["--path", tf.name, "--db", "testing", "--host", ip], input="postgres")
    assert result.exit_code == 0


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_send_message(runner, access_token, reset_tiny_db):
    device_id = "23"
    user_id = "1"
    key = "fcf064e7ea97ab828ba80578d255942e648c872d8d0c09a051bf5424640f2e68"
    result = runner.invoke(cmd.send_message, [user_id, device_id, "test"])
    assert f"Keys for device {device_id} not present, please use:" in result.output

    insert_into_tinydb(cmd.path, 'device_keys', {'device_id': device_id, 'shared_key': key})
    insert_into_tinydb(cmd.path, "credentials", {"broker_id": "4", "broker_password": 'test_pass'})

    result = runner.invoke(cmd.send_message, [user_id, device_id, "test"])
    assert "Data published" in result.output
    assert "RC and MID = (0, 1)" in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_send_column_keys(runner, access_token, reset_tiny_db):
    device_id = "23"
    user_id = "1"
    key = "fcf064e7ea97ab828ba80578d255942e648c872d8d0c09a051bf5424640f2e68"
    result = runner.invoke(cmd.send_column_keys, [user_id, device_id])
    assert f"Keys for device {device_id} not present, please use:" in result.output

    insert_into_tinydb(cmd.path, 'device_keys', {'device_id': device_id, 'shared_key': key})
    insert_into_tinydb(cmd.path, "credentials", {"broker_id": "4", "broker_password": 'test_pass'})

    result = runner.invoke(cmd.send_column_keys, [user_id, device_id])
    assert "Data published" in result.output
    assert "RC and MID = (0, 1)" in result.output

    doc = search_tinydb_doc(cmd.path, 'device_keys', Query().device_id == device_id)
    assert "action:name" in doc
    assert len(doc) == 12

    fernet_key = hex_to_fernet(doc["device:name"])
    assert isinstance(fernet_key, Fernet)
    cipher = hex_to_ope(doc["device_data:added"])
    assert isinstance(cipher, OPE)


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_get_device_data(runner, access_token, app_and_ctx, reset_tiny_db, col_keys):
    device_id = 23
    user_id = "1"
    r = Mock()
    r.content = b'{\n  "device_data": [\n    {\n      "added": 2116572382, \n      "correctness_hash": "$2b$12$GxqMXIMKiEtrOF9YVL2TO.S7vf7Jc4RP8MXgL9d0kgIJfthUQjxM6", \n      "data": "gAAAAABcUvNYE3fPNwjf2yVvpjzYDiXn2Nx_Yjrp2vXQEu5jBWoQUZUY1VdPZqdw4xU_WqmNHR28Jm742aXvZxqWycGOUOWHJQ==", \n      "device_id": 23, \n      "id": 6, \n      "num_data": 464064, \n      "tid": "gAAAAABcUvNYaVEWRG5vxlvTBgj0TVP9icLDThlR5sxYlfPOP8eNoFcWkCoPNyGK5mFuS9Ia2WQ_gEFsdiKpG4cnPsg2uYSTvA==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxuN5X.DMkHilBYQSsUWodebAG.asbqKNa"\n    }, \n    {\n      "added": 2244032082, \n      "correctness_hash": "$2b$12$panqbBvEIAG4/7ct77LyieP017hCkKeZ6cubdQo4fcJpHOoA6UbPO", \n      "data": "gAAAAABcUvNYjVUDLeMntE0dyztMI1tv0zvHzNMgPZhr302ozcsXXTSKMLtudy8arSyYHiwk7Gyg_gSc5FN2-zWTooe0UNBV9g==", \n      "device_id": 23, \n      "id": 8, \n      "num_data": 466263, \n      "tid": "gAAAAABcUvNYvD4xkZ7pHxIBtpEWka8UVdCxmvR-O886BC06ILrqWqtT59ZKVgz7k8-TtIstlYzubq1ZZp_prquskFw5ZWNVSQ==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI."\n    }, \n    {\n      "added": 2328638717, \n      "correctness_hash": "$2b$12$CwcoYDiksZSEIvQpwWE8KurDopFpaofsfYW7Y67Ifonv.a7ZDe0SW", \n      "data": "gAAAAABcUvNYI5KEn0rbmD_8rORWcHHpvVGrvk1mpgPdagaPjxTFVu3LzQITjiZLIQtP6uHgmQax515HL-8oTwUQA7ewIjv8CA==", \n      "device_id": 23, \n      "id": 4, \n      "num_data": 471232, \n      "tid": "gAAAAABcUvNYhiqIYBpG848jbgdwY92eW2HUGSwjAP4NL9rAcSCTmeU2noYgDnlpy7XzLDu4Ly4UaGMjBqUeNlpryV_BEYbcug==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxuSfVK9H/a.JO/whZHvsU1Q39d26XzS/6"\n    }, \n    {\n      "added": 2893046721, \n      "correctness_hash": "$2b$12$wvleRl6BZXh59slt2gPoyuEgKzmPCo.lZheLo2gYlVeQEk016oUMq", \n      "data": "gAAAAABcUvNY45bp9Q8D_rS2xTcM241zTXMIWSM4vqtkmG1_phcP_qpCG5Ncw6vBKpgjVywNvZJMLOruBVumOq745jtxOqlDEA==", \n      "device_id": 23, \n      "id": 12, \n      "num_data": 468360, \n      "tid": "gAAAAABcUvNY8h6dQrIaMAYm-9Mp2-ykEqOxc3BII_N_u8a6g1rP4JZRqjeAqGPivYAQFMC1Wkq0y2xyBv612yFVBGFBVXs3_Q==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxupooniyevX3UXhzktSF2tYwePP7PnQ6C"\n    }, \n    {\n      "added": -262258, \n      "correctness_hash": "$2b$12$06Scc4tIoGiCKsnYnQnTruIHPMWSG1xzUBeVG66G.kNgWLMi0za/W", \n      "data": "gAAAAABcVAyxgzeyy5pV2rG_GMca09tHlg1Hkg-Tc7HSsZaP-zRTiPXS8O5S0uWVxkfIlNiJuqh8dLGletISgyAwVKfxn3CrGQ==", \n      "device_id": 23, \n      "id": 26, \n      "num_data": 459731, \n      "tid": "gAAAAABcVAyxVbuRTSaOe9TU7ye3_2uJ6Yp9PKJz0ASCjKKb9MKGXvAJVK71i7KV4LNWgBYrGEJXLko3iSOK7uIbvBrZeCZxLQ==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI."\n    }\n  ], \n  "success": true\n}\n'
    cmd.fake_tuple_data = {'device_data': {'added': {'function_name': 'triangle_wave', 'lower_bound': 1, 'upper_bound': 1, 'is_numeric': True}, 'num_data': {'function_name': 'sawtooth_wave', 'lower_bound': 1, 'upper_bound': 1, 'is_numeric': True}, 'data': {'function_name': 'square_wave', 'lower_bound': 1, 'upper_bound': 1, 'is_numeric': False}, 'tid': {'function_name': 'index_function', 'lower_bound': 1, 'upper_bound': 1, 'is_numeric': False}}}

    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    app, ctx = app_and_ctx
    with app.app_context():
        with mock.patch('requests.post', return_value=r):
            with mock.patch('client.user.commands._get_fake_tuple_data') as _get_fake_tuple_data:
                result = runner.invoke(cmd.get_device_data, [user_id, str(device_id), '--token', access_token])
                assert "Data Integrity satisfied." in result.output
                assert "failed correctness hash test!" not in result.output

                r.content = b'{\n  "device_data": [\n    {\n      "added": 2116572382, \n      "correctness_hash": "$2b$12$GeqMXIMKiE6rOF9YVL2TO.S7vf7Jc4RP8MXgL9d0kgIJfthUQjxM6", \n      "data": "gAAAAABcUvNYE3fPNwjf2yVvpjzYDiXn2Nx_Yjrp2vXQEu5jBWoQUZUY1VdPZqdw4xU_WqmNHR28Jm742aXvZxqWycGOUOWHJQ==", \n      "device_id": 23, \n      "id": 6, \n      "num_data": 464064, \n      "tid": "gAAAAABcUvNYaVEWRG5vxlvTBgj0TVP9icLDThlR5sxYlfPOP8eNoFcWkCoPNyGK5mFuS9Ia2WQ_gEFsdiKpG4cnPsg2uYSTvA==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxuN5X.DMkHilBYQSsUWodebAG.asbqKNa"\n    }, \n    {\n      "added": 2244032082, \n      "correctness_hash": "$2b$12$panqbBvEIAG4/7ct77LyieP017hCkKeZ6cubdQo4fcJpHOoA6UbPO", \n      "data": "gAAAAABcUvNYjVUDLeMntE0dyztMI1tv0zvHzNMgPZhr302ozcsXXTSKMLtudy8arSyYHiwk7Gyg_gSc5FN2-zWTooe0UNBV9g==", \n      "device_id": 23, \n      "id": 8, \n      "num_data": 466263, \n      "tid": "gAAAAABcUvNYvD4xkZ7pHxIBtpEWka8UVdCxmvR-O886BC06ILrqWqtT59ZKVgz7k8-TtIstlYzubq1ZZp_prquskFw5ZWNVSQ==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI."\n    }, \n    {\n      "added": 2328638717, \n      "correctness_hash": "$2b$12$CwcoYDiksZSEIvQpwWE8KurDopFpaofsfYW7Y67Ifonv.a7ZDe0SW", \n      "data": "gAAAAABcUvNYI5KEn0rbmD_8rORWcHHpvVGrvk1mpgPdagaPjxTFVu3LzQITjiZLIQtP6uHgmQax515HL-8oTwUQA7ewIjv8CA==", \n      "device_id": 23, \n      "id": 4, \n      "num_data": 471232, \n      "tid": "gAAAAABcUvNYhiqIYBpG848jbgdwY92eW2HUGSwjAP4NL9rAcSCTmeU2noYgDnlpy7XzLDu4Ly4UaGMjBqUeNlpryV_BEYbcug==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxuSfVK9H/a.JO/whZHvsU1Q39d26XzS/6"\n    }, \n    {\n      "added": 2893046721, \n      "correctness_hash": "$2b$12$wvleRl6BZXh59slt2gPoyuEgKzmPCo.lZheLo2gYlVeQEk016oUMq", \n      "data": "gAAAAABcUvNY45bp9Q8D_rS2xTcM241zTXMIWSM4vqtkmG1_phcP_qpCG5Ncw6vBKpgjVywNvZJMLOruBVumOq745jtxOqlDEA==", \n      "device_id": 23, \n      "id": 12, \n      "num_data": 468360, \n      "tid": "gAAAAABcUvNY8h6dQrIaMAYm-9Mp2-ykEqOxc3BII_N_u8a6g1rP4JZRqjeAqGPivYAQFMC1Wkq0y2xyBv612yFVBGFBVXs3_Q==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxupooniyevX3UXhzktSF2tYwePP7PnQ6C"\n    }, \n    {\n      "added": -262258, \n      "correctness_hash": "$2b$12$06Scc4tIoGiCKsnYnQnTruIHPMWSG1xzUBeVG66G.kNgWLMi0za/W", \n      "data": "gAAAAABcVAyxgzeyy5pV2rG_GMca09tHlg1Hkg-Tc7HSsZaP-zRTiPXS8O5S0uWVxkfIlNiJuqh8dLGletISgyAwVKfxn3CrGQ==", \n      "device_id": 23, \n      "id": 26, \n      "num_data": 459731, \n      "tid": "gAAAAABcVAyxVbuRTSaOe9TU7ye3_2uJ6Yp9PKJz0ASCjKKb9MKGXvAJVK71i7KV4LNWgBYrGEJXLko3iSOK7uIbvBrZeCZxLQ==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI."\n    }\n  ], \n  "success": true\n}\n'
                cmd.fake_tuple_data = {'device_data': {'added': {'function_name': 'triangle_wave', 'lower_bound': 1, 'upper_bound': 2, 'is_numeric': True},
                                                       'num_data': {'function_name': 'sawtooth_wave', 'lower_bound': 1, 'upper_bound': 2, 'is_numeric': True},
                                                       'data': {'function_name': 'square_wave', 'lower_bound': 1, 'upper_bound': 2, 'is_numeric': False},
                                                       'tid': {'function_name': 'index_function', 'lower_bound': 1, 'upper_bound': 2, 'is_numeric': False}}}

                result = runner.invoke(cmd.get_device_data, [user_id, str(device_id), '--token', access_token])
                assert "Data Integrity NOT satisfied." in result.output
                assert "failed correctness hash test!" in result.output
    cmd.fake_tuple_data = None


def test_get_fake_tuple_data(capsys):
    device_id = 23
    user_id = 1
    valid_payload = b'{"device_data": {"added": {'\
                    b'"function_name": "triangle_wave",'\
                    b'"lower_bound": 12,'\
                    b'"upper_bound": 11,'\
                    b'"is_numeric": true }}}'
    mqtt_client = Mock()

    invalid_msg = MQTTMessage(topic=b"x:%a/g:%a" % (device_id, user_id))
    invalid_msg.payload = valid_payload

    cmd._handle_on_message(mqtt_client, None, invalid_msg, device_id, user_id)
    assert cmd.fake_tuple_data is None
    captured = capsys.readouterr()
    assert f"Received invalid topic: {invalid_msg.topic}" in captured.out

    msg = MQTTMessage(topic=b"d:%a/u:%a" % (device_id, user_id))
    msg.payload = b'{"device_data": {"added": { ... Invalid payload'

    cmd._handle_on_message(mqtt_client, None, msg, device_id, user_id)
    assert cmd.fake_tuple_data is None
    captured = capsys.readouterr()
    assert f"Received invalid payload: {msg.payload.decode()}" in captured.out

    msg.payload = valid_payload

    cmd._handle_on_message(mqtt_client, None, msg, device_id, user_id)
    mqtt_client.disconnect.assert_called_once()
    assert cmd.fake_tuple_data == {'device_data': {'added': {'function_name': 'triangle_wave', 'lower_bound': 12, 'upper_bound': 11, 'is_numeric': True}}}


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_divide_fake_and_real_data(reset_tiny_db, col_keys):
    device_id = 23
    rows = [{
      "added": 2116572382,
      "correctness_hash": "$2b$12$GxqMXIMKiEtrOF9YVL2TO.S7vf7Jc4RP8MXgL9d0kgIJfthUQjxM6",
      "data": "gAAAAABcUvNYE3fPNwjf2yVvpjzYDiXn2Nx_Yjrp2vXQEu5jBWoQUZUY1VdPZqdw4xU_WqmNHR28Jm742aXvZxqWycGOUOWHJQ==",
      "device_id": 23,
      "id": 6,
      "num_data": 464064,
      "tid": "gAAAAABcUvNYaVEWRG5vxlvTBgj0TVP9icLDThlR5sxYlfPOP8eNoFcWkCoPNyGK5mFuS9Ia2WQ_gEFsdiKpG4cnPsg2uYSTvA==",
      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxuN5X.DMkHilBYQSsUWodebAG.asbqKNa"
    },
    {
      "added": 2244032082,
      "correctness_hash": '$2b$12$IG7lSJbUlJ2xxPlWvHwWN.gowMe/Xqg/lxmueyqlaBI4TCHE.BxU2',  # Fake
      "data": "gAAAAABcUvNYjVUDLeMntE0dyztMI1tv0zvHzNMgPZhr302ozcsXXTSKMLtudy8arSyYHiwk7Gyg_gSc5FN2-zWTooe0UNBV9g==",
      "device_id": 23,
      "id": 8,
      "num_data": 466263,
      "tid": "gAAAAABcUvNYvD4xkZ7pHxIBtpEWka8UVdCxmvR-O886BC06ILrqWqtT59ZKVgz7k8-TtIstlYzubq1ZZp_prquskFw5ZWNVSQ==",
      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI."
    },
    {
      "added": 2328638717,
      "correctness_hash": '$2b$12$eWHqbmbvv.Egj/4Jy3.msOdnZ0vz.iaMRdgHJ5d9/Ymmczjr7wbcK',  # Fake
      "data": "gAAAAABcUvNYI5KEn0rbmD_8rORWcHHpvVGrvk1mpgPdagaPjxTFVu3LzQITjiZLIQtP6uHgmQax515HL-8oTwUQA7ewIjv8CA==",
      "device_id": 23,
      "id": 4,
      "num_data": 471232,
      "tid": "gAAAAABcUvNYhiqIYBpG848jbgdwY92eW2HUGSwjAP4NL9rAcSCTmeU2noYgDnlpy7XzLDu4Ly4UaGMjBqUeNlpryV_BEYbcug==",
      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxuSfVK9H/a.JO/whZHvsU1Q39d26XzS/6"
    }]

    integrity_info = {'device_data': {
        'added': {'function_name': 'triangle_wave', 'lower_bound': 1, 'upper_bound': 4, 'is_numeric': True},
        'num_data': {'function_name': 'sawtooth_wave', 'lower_bound': 1, 'upper_bound': 4, 'is_numeric': True},
        'tid': {'function_name': 'square_wave', 'lower_bound': 1, 'upper_bound': 4, 'is_numeric': False},
        'data': {'function_name': 'square_wave', 'lower_bound': 1, 'upper_bound': 4, 'is_numeric': False}
    }}

    insert_into_tinydb(cmd.path, 'device_keys', col_keys)

    fake, real = cmd._divide_fake_and_real_data(rows, device_id, integrity_info)
    assert len(fake) == 2
    assert len(real) == 1
    assert real[0]["tid"] == '1'
    assert "added" in real[0] and "data" in real[0] and "num_data" in real[0] and "tid" in real[0] and "correctness_hash" in real[0]
    assert "device_id" not in real[0] and "id" not in real[0] and "tid_bi" not in real[0]


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_get_encryption_keys(reset_tiny_db):
    device_id = 23
    data = {"device_id": str(device_id),
            "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "action:name": "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d",
            "device_type:description": "2c567c6fde8d29ee3c1ac15e74692089fdce507a43eb931be792ec3887968d33",
            "device_data:added": "5b27b633b2ea8fd12617d36dc0e864b2e8c6e57e809662e88fe56d70d033429e",
            "device_data:num_data": "ed1b6067e3dec82b4b61360c29eaeb785987e0c36bfdba454b9eca2d1622ecc2",
            "device_data:data": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "scene:name": "7c2a6bb5e7021e30c7326bdb99003fd43b2b0770b0a4a07f7b3876634b11ff94",
            "scene:description": "d011b0fa5a23b3c2efadb2e0fea094647ff7b03b9a93022aeae6c1edf3eb1871"}

    insert_into_tinydb(cmd.path, 'device_keys', data)
    result = cmd.get_encryption_keys(device_id, ["device_data:added", "scene:name"])
    assert result == {
        "device_data:added": "5b27b633b2ea8fd12617d36dc0e864b2e8c6e57e809662e88fe56d70d033429e",
        "scene:name": "7c2a6bb5e7021e30c7326bdb99003fd43b2b0770b0a4a07f7b3876634b11ff94"
    }


def test_get_col_encryption_type():
    col_name = "device_data:added"
    integrity_info = {
        'device_data': {
            'added': {
                'function_name': 'triangle_wave',
                'lower_bound': 1,
                'upper_bound': 1,
                'is_numeric': True},
            'data': {
                'function_name': 'square_wave',
                'lower_bound': 1,
                'upper_bound': 1,
                'is_numeric': False}}}

    assert cmd.get_col_encryption_type(col_name, integrity_info)

    col_name = "device_data:data"
    assert not cmd.get_col_encryption_type(col_name, integrity_info)


def test_decrypt_row():
    row = {
      "added": 2116572382,
      "data": "gAAAAABcUvNYE3fPNwjf2yVvpjzYDiXn2Nx_Yjrp2vXQEu5jBWoQUZUY1VdPZqdw4xU_WqmNHR28Jm742aXvZxqWycGOUOWHJQ==",
      "num_data": 464064,
      "tid": "gAAAAABcUvNYaVEWRG5vxlvTBgj0TVP9icLDThlR5sxYlfPOP8eNoFcWkCoPNyGK5mFuS9Ia2WQ_gEFsdiKpG4cnPsg2uYSTvA==",
    }

    keys = {
        "added": ["8dabfaf75c380f03e95f55760af02dc84026654cf2019d6da44cc69f600ba8f7", True],
        "num_data": ["3130d649f90006ef90f5c28fd486a6e748ffc35bad4981799708a411f7acaa60", True],
        "tid": ["9692e6525c19e6fa37978626606534015cd120816a28b501bebec142d86002b2", False],
        "data": ["af785b829c4502286f5abec3403b43324971acfdb22fd80007216e8fa1abbf2e", False]
    }

    expected = {
        "added": 985734000,
        "num_data": 1000,
        "data": "test1",
        "tid": "1"
    }

    result = cmd.decrypt_row(row, keys)
    assert expected == result


def test_is_fake():
    row_values = [-959, 1000, -980, 1]
    row_correctness_hash = '$2b$12$p6bfP/Nl15D0m.xejbTUuei.qYEsDJYd6mKjuKBST5iZwZkvgeX3G'
    assert cmd.is_fake(row_values, row_correctness_hash)

    row_correctness_hash = '$2b$12$7RnvQxSG1USqFj73rrFq6uIae/CZh7cLxNAwTZwoWa.Zk04PxipNW'
    assert not cmd.is_fake(row_values, row_correctness_hash)


def test_generate_fake_tuples_in_range():
    fake_tuple_info = {
        "added": {"function_name": "triangle_wave", "lower_bound": 2, "upper_bound": 5, "is_numeric": True},
        "num_data": {"function_name": "sawtooth_wave", "lower_bound": 2, "upper_bound": 5, "is_numeric": True},
        "data": {"function_name": "square_wave", "lower_bound": 2, "upper_bound": 5, "is_numeric": False},
        "tid": {"function_name": "index_function", "lower_bound": 2, "upper_bound": 5, "is_numeric": False},
    }
    fake_tuples = cmd.generate_fake_tuples_in_range(fake_tuple_info)

    assert len(fake_tuples) == 4
    assert "added" in fake_tuples[0] and "num_data" in fake_tuples[0] and "data" in fake_tuples[0] and "tid" in fake_tuples[0]
    assert fake_tuples[0] == {'added': -919, 'num_data': -959, 'data': "1000", "tid": "3"}


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_parse_msg(runner, reset_tiny_db):
    data = """{"ciphertext": "gAAAAABcOiilUJ_u1tRSQ-iIghG4DgPOfCjUXOL2_FZ0f2XcPHcp5rDMu1dQMvFZ_4VlPr-QjG79HNes-F6bDxcr7K03R0r-8bWEZaFcS3j-ri0C-sy33Fc=", "user_id": 1}"""

    insert_into_tinydb(device_cmd.path, 'users', {"id": 1, "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc"})
    result = runner.invoke(device_cmd.parse_msg, [data])
    assert "{\"action\": true}" in result.output


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_save_column_keys(runner, reset_tiny_db):
    data = """{"device_data:data": "gAAAAABcRHiboBSiAuKLxvSqS1yu4vOR8FlqGBOnzJSQ85e5UShmQ9avtLAXx_w9fKad2xILHWbi_uFywJML8ukoDGB7iiHkLT39iOnrUCAQHFyOdFERixgl-iFHMji-S1YfGKGwxRIU", "device_data:num_data": "gAAAAABcRHibuWXtMvF7XgSN7FR-cHyNl2eDb_HHPCuTjqtdMN2VxxZnSxGCjkoJxRNIGMcpBW-z4n1wynPoCCb1VanmH3EukMPwpf7Vwk9WytkNR9h51ApyGt1QEkaj_JF2A5jKu-vw", "action:name": "gAAAAABcRHibSiR3cHtaSUSk1ipKP_7csl3xTCd4J-JesU8GPlC2iwfblksE3kvuV3U2mAYqiYe3UuYw04JPbYDYaFePY-YTUAzie3OCRzwuMTE6tE9UBJtJ8wUNJSctZnrvSi0rcPzQ", "device_type:description": "gAAAAABcRHibvjQEIYiaSi9yXLm2VPbgPsmye1mKv9DYF9ktCixOf6Cq03dKc1-ZpxucfrKJXOyT7vyq17cfxyrN9k-Bj4pi3BV7M68fLTR__03lK32W8LOLkMLWdMvxcURU1W8gg91f", "device:name": "gAAAAABcRHib0mxfmRE3mg4ALX3XPjP7ZuVQ69NiRdebiNCE-40wZuzzNV1krKcnZeRZVWXwYf4xjYLNNygY-kbbgxltBWNJ5rLanpBIqTeoq8uI9up1bZ_vFFCiGPIjHTpYkMnF5XIN", "device:status": "gAAAAABcRHiboBSiAuKLxvSqS1yu4vOR8FlqGBOnzJSQ85e5UShmQ9avtLAXx_w9fKad2xILHWbi_uFywJML8ukoDGB7iiHkLT39iOnrUCAQHFyOdFERixgl-iFHMji-S1YfGKGwxRIU", "device_data:added": "gAAAAABcRHibuWXtMvF7XgSN7FR-cHyNl2eDb_HHPCuTjqtdMN2VxxZnSxGCjkoJxRNIGMcpBW-z4n1wynPoCCb1VanmH3EukMPwpf7Vwk9WytkNR9h51ApyGt1QEkaj_JF2A5jKu-vw", "scene:name": "gAAAAABcRHibVgsVHRls8IGj95TdFKraKbGfyf_TvDzjg0KV_vu-HawiISBzRaxwrFV_QHI5jA73CTM2dF4ePENaMe0QtIJljtqCBUSRhoQideCy0JL4hDAIJUzpGXFK5RMC2fJHUJ17", "scene:description": "gAAAAABcRHib1iH0Bs9sHff-dt7FY9XOUDzARN-mwaq7eI7iLYYwtmBcMkB3T5ChNnoNWhIRLnh_lQLmvCT_itBvjoIHydBVdIcTjzsyHcTMBUdlxPmohokOjunxdMSCY0B48-pYqzsn", "user_id": 1}"""

    insert_into_tinydb(device_cmd.path, 'users', {"id": 1, "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc"})
    runner.invoke(device_cmd.save_column_keys, [data])

    table = get_tinydb_table(device_cmd.path, 'users')
    doc = table.get(Query().id == 1)
    assert "action:name" in doc
    assert len(doc) == 11
    fernet_key = hex_to_fernet(doc["device:status"])
    assert isinstance(fernet_key, Fernet)
    cipher = hex_to_ope(doc["device_data:added"])
    assert isinstance(cipher, OPE)


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_register_to_broker(change_to_dev_db, runner, access_token_tree, reset_tiny_db):
    password = "some_bad_pass"
    app, ctx = change_to_dev_db
    with app.app_context():
        creds = db.session.query(User).filter(User.access_token == access_token_tree).first().mqtt_creds

    runner.invoke(cmd.register_to_broker, [password, '--token', access_token_tree])
    table = get_tinydb_table(cmd.path, 'credentials')
    doc = table.search(where('broker_id').exists() & where('broker_password').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1
    assert doc[0]["broker_password"] == password

    with app.app_context():
        creds_new = db.session.query(User).filter(User.access_token == access_token_tree).first().mqtt_creds
        assert creds is None
        assert len(creds_new.acls) == 2
        to_delete = db.session.query(MQTTUser).filter(MQTTUser.username == creds_new.username).first()
        db.session.delete(to_delete)


def test_create_device_type(runner, access_token):
    result = runner.invoke(cmd.create_device_type, ["description", '--token', access_token])
    assert "\"success\": true," in result.output
    assert "\"type_id\": " in result.output


def test_create_device(runner, access_token):  # TODO this inserts record to dev DB - do clean-up with `change_to_dev_db`
    result = runner.invoke(cmd.create_device_type, ["description-again", '--token', access_token])
    type_id = re.search('type_id": "(.+)"', result.output, re.IGNORECASE).group(1)
    result = runner.invoke(cmd.create_device, [type_id, "1", "CLITest", "test_pass", '--token', access_token])
    assert "\"success\": true" in result.output
    assert "\"id\": " in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_get_device(runner, client, access_token, reset_tiny_db, col_keys):
    device_name = "my_raspberry"
    user_id = "1"
    device_name_bi = hash(device_name, user_id)

    insert_into_tinydb(cmd.path, 'device_keys', col_keys)

    result = runner.invoke(cmd.get_devices, [device_name, user_id, '--token', access_token])
    assert device_name_bi in result.output
    assert "failed correctness hash test!" not in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_get_device_data_by_num_range(runner, client, access_token, reset_tiny_db, col_keys):
    device_id = "23"
    message_fail = "Data Integrity NOT satisfied."
    message_success = "Data Integrity satisfied."
    r = Mock()
    r.content = b'{\n  "device_data": [\n    {\n      "added": 2116572382, \n      "correctness_hash": "$2b$12$GxqMXIMKiEtrOF9YVL2TO.S7vf7Jc4RP8MXgL9d0kgIJfthUQjxM6", \n      "data": "gAAAAABcUvNYE3fPNwjf2yVvpjzYDiXn2Nx_Yjrp2vXQEu5jBWoQUZUY1VdPZqdw4xU_WqmNHR28Jm742aXvZxqWycGOUOWHJQ==", \n      "device_id": 23, \n      "id": 6, \n      "num_data": 464064, \n      "tid": "gAAAAABcUvNYaVEWRG5vxlvTBgj0TVP9icLDThlR5sxYlfPOP8eNoFcWkCoPNyGK5mFuS9Ia2WQ_gEFsdiKpG4cnPsg2uYSTvA==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxuN5X.DMkHilBYQSsUWodebAG.asbqKNa"\n    }, \n    {\n      "added": -262258, \n      "correctness_hash": "$2b$12$WwnNuG0K6/F.TnHUF4TsgOHX1xs1W1Y9TiR2nOEhhaeSaXWI7boqu", \n      "data": "gAAAAABcVC9yMWlcTwDZfvoJ_9VsJYqZF_x4iRQ1SrFlFOA6Qda1vBIbT9v1rtRk-qIdpKFVR6oNFT4tFdPzDKRvPbRQrVZFxQ==", \n      "device_id": 23, \n      "id": 26, \n      "num_data": 459731, \n      "tid": "gAAAAABcVC9y-Abn8uvuN1lGCW7qvdGY2IHfsrl3zCIOP7FDa01oDvBy-vc3gRbuNdA2Elrko2Kahqdg5oagdGkVF6VnO02msw==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI."\n    }\n  ], \n  "success": true\n}\n'
    cmd.fake_tuple_data = {'device_data': {'added': {'function_name': 'triangle_wave', 'lower_bound': 1, 'upper_bound': 1, 'is_numeric': True},
                                           'num_data': {'function_name': 'sawtooth_wave', 'lower_bound': 1, 'upper_bound': 1, 'is_numeric': True},
                                           'data': {'function_name': 'square_wave', 'lower_bound': 1, 'upper_bound': 1, 'is_numeric': False},
                                           'tid': {'function_name': 'index_function', 'lower_bound': 1, 'upper_bound': 1, 'is_numeric': False}}}

    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    with mock.patch('client.user.commands._get_fake_tuple_data') as _get_fake_tuple_data:
        result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, '--token', access_token])
        assert "failed correctness hash test!" not in result.output
        assert message_fail in result.output
        json_output = json_string_with_bytes_to_dict(result.output.split(message_fail)[1])
        assert len(json_output["device_data"]) == 4

        result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, "--lower", 467297, '--token', access_token])
        assert "failed correctness hash test!" not in result.output
        assert message_success in result.output
        json_output = json_string_with_bytes_to_dict(result.output.split(message_success)[1])
        assert len(json_output["device_data"]) == 2

        result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, "--lower", 467297, "--upper", 469439, '--token', access_token])
        assert "failed correctness hash test!" not in result.output
        assert message_success in result.output
        json_output = json_string_with_bytes_to_dict(result.output.split(message_success)[1])
        assert len(json_output["device_data"]) == 1

        result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, "--upper", 467717, '--token', access_token])
        assert "failed correctness hash test!" not in result.output
        assert message_fail in result.output
        json_output = json_string_with_bytes_to_dict(result.output.split(message_fail)[1])
        assert len(json_output["device_data"]) == 2

        with mock.patch('requests.post', return_value=r):
            result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, "--lower", 459679, "--upper", 465192, '--token', access_token])
            assert "failed correctness hash test!" not in result.output
            assert message_success in result.output
            json_output = json_string_with_bytes_to_dict(result.output.split(message_success)[1])
            assert len(json_output["device_data"]) == 1

            r.content = b'{\n  "device_data": [\n    {\n      "added": 2116572382, \n      "correctness_hash": "$2b$12$GxqMX2MKiEtrOF9YVL2TO.S7vf7Jc4RP8MXgL9d0kgIJfthUQjxM6", \n      "data": "gAAAAABcUvNYE3fPNwjf2yVvpjzYDiXn2Nx_Yjrp2vXQEu5jBWoQUZUY1VdPZqdw4xU_WqmNHR28Jm742aXvZxqWycGOUOWHJQ==", \n      "device_id": 23, \n      "id": 6, \n      "num_data": 464064, \n      "tid": "gAAAAABcUvNYaVEWRG5vxlvTBgj0TVP9icLDThlR5sxYlfPOP8eNoFcWkCoPNyGK5mFuS9Ia2WQ_gEFsdiKpG4cnPsg2uYSTvA==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxuN5X.DMkHilBYQSsUWodebAG.asbqKNa"\n    }, \n    {\n      "added": -262258, \n      "correctness_hash": "$2b$12$WwnNuG0K6/F.TnHUF4TsgOHX1xs1W1Y9TiR2nOEhhaeSaXWI7boqu", \n      "data": "gAAAAABcVC9yMWlcTwDZfvoJ_9VsJYqZF_x4iRQ1SrFlFOA6Qda1vBIbT9v1rtRk-qIdpKFVR6oNFT4tFdPzDKRvPbRQrVZFxQ==", \n      "device_id": 23, \n      "id": 26, \n      "num_data": 459731, \n      "tid": "gAAAAABcVC9y-Abn8uvuN1lGCW7qvdGY2IHfsrl3zCIOP7FDa01oDvBy-vc3gRbuNdA2Elrko2Kahqdg5oagdGkVF6VnO02msw==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI."\n    }\n  ], \n  "success": true\n}\n'
            result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, "--lower", 459679, "--upper", 465192, '--token', access_token])
            assert "failed correctness hash test!" in result.output

    cmd.fake_tuple_data = None


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_slice_by_range(reset_tiny_db, col_keys):
    device_id = 23
    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    lower = 459679  # -1000
    upper = 465192  # 1000
    result = cmd.slice_by_range(device_id, [{'added': -959, 'num_data': -980, 'data': '1000', 'tid': '2'}, {'added': -959, 'num_data': 1700, 'data': '1000', 'tid': '2'}], lower, upper, "device_data:num_data")
    assert result == [{'added': -959, 'num_data': -980, 'data': '1000', 'tid': '2'}]


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_send_key_to_device(runner, access_token_two, reset_tiny_db):
    device_id = '45'
    device_id_2 = '34'

    result = runner.invoke(cmd.send_key_to_device, [device_id, '--token', access_token_two])
    assert "\"success\": true" in result.output
    result = runner.invoke(cmd.send_key_to_device, [device_id_2, '--token', access_token_two])
    assert "\"success\": true" in result.output

    table = get_tinydb_table(cmd.path, 'device_keys')
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
    table = get_tinydb_table(path_string, 'aa_keys')
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
    runner.invoke(device_cmd.init, ["23", "test_password"])
    table = get_tinydb_table(device_cmd.path, 'device')
    doc = table.search(where('id').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1
    assert int(doc[0]['id']) == 23


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_device_receive_pk(runner, reset_tiny_db):
    data = "{'user_public_key': '-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8z5FnI9EoJZmxSXmKItAvZcdL/bjd4VM\nI2KCZU5gud4R034+VKfy0ameLSty3ImUzoOCClkXAvSBqIe+qKRuteGBeCrnVaIV\nWyk8DgOt4Y2Pp3W9Tm/5dRdxxl8RkCg7\n-----END PUBLIC KEY-----\n', 'user_id': '1'}"

    result = runner.invoke(device_cmd.receive_pk, [data])
    table = get_tinydb_table(device_cmd.path, 'users')
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

    table = get_tinydb_table(cmd.path, 'device_keys')
    table.insert({
        "device_id": "99",
        "public_key": "anything",
        "private_key": "anything"
    })

    result = runner.invoke(cmd.retrieve_device_public_key, ["99", '--token', access_token])
    assert "\"success\": false" in result.output

    table.insert({
        "device_id": str(device_id),
        "public_key": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEP1oBLtMBa94A6IxKINUkIaOJRYShIsr+\nxu7H3ObkRljibL139knm8XXCTXG5jG/IIJvBdsDmTiHwPznZ0KRN9oIAc+CUqIeU\nUkEPQ87XAYqS2WTgg8vTPOml/htk3QbN\n-----END PUBLIC KEY-----\n",
        "private_key": "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDA9Nyrj4U915ZY6H//GY9o7WwchqnxqrUt8aIh64hfM9141yQa5qnTz\nTJCsZRcZSPSgBwYFK4EEACKhZANiAAQ/WgEu0wFr3gDojEog1SQho4lFhKEiyv7G\n7sfc5uRGWOJsvXf2SebxdcJNcbmMb8ggm8F2wOZOIfA/OdnQpE32ggBz4JSoh5RS\nQQ9DztcBipLZZOCDy9M86aX+G2TdBs0=\n-----END EC PRIVATE KEY-----\n"
    })

    runner.invoke(cmd.retrieve_device_public_key, [device_id, '--token', access_token])

    doc = search_tinydb_doc(cmd.path, 'device_keys', Query().device_id == device_id)
    assert "device_id" in doc and "shared_key" in doc
    assert "public_key" not in doc and "master_key" not in doc, "public_key and master_key should not be present anymore (Ephemeral keys need to be wiped)."


def test_dict_to_payload():
    kwargs = {
        "key1": "value",
        "key2": 1,
        "another": False,
    }

    result = device_cmd.dict_to_payload(**kwargs)

    assert result == '{"key1": "value", "key2": 1, "another": false}'


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
    device_id_doc = {"id": "23"}
    data = {"id": user_id,
            "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "action:name": "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d",
            "device_type:description": "2c567c6fde8d29ee3c1ac15e74692089fdce507a43eb931be792ec3887968d33",
            "device_data:added": "5b27b633b2ea8fd12617d36dc0e864b2e8c6e57e809662e88fe56d70d033429e",
            "device_data:num_data": "ed1b6067e3dec82b4b61360c29eaeb785987e0c36bfdba454b9eca2d1622ecc2",
            "device_data:data": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "device_data:tid": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "scene:name": "7c2a6bb5e7021e30c7326bdb99003fd43b2b0770b0a4a07f7b3876634b11ff94",
            "scene:description": "d011b0fa5a23b3c2efadb2e0fea094647ff7b03b9a93022aeae6c1edf3eb1871"}

    insert_into_tinydb(device_cmd.path, 'users', data)
    insert_into_tinydb(device_cmd.path, 'device', device_id_doc)
    result = runner.invoke(device_cmd.get_fake_tuple, [str(user_id), "upper_bound"])
    table = get_tinydb_table(device_cmd.path, 'users')
    doc = table.get(Query().id == user_id)
    assert "integrity" in doc, "Integrity sub-document wasn't inserted."
    assert all(val in doc["integrity"]["device_data"] for val in ["data", "num_data", "added"])

    search_res = re.findall('\"(tid|data|num_data|added|correctness_hash)\": \"?([^:,\"]+)\"?', result.output)

    assert len(search_res) == 5

    column, ciphertext = next(pair for pair in search_res if pair[0] == "data")
    plaintext = decrypt_using_fernet_hex(data[f"device_data:{column}"], ciphertext)
    assert plaintext.decode() == "1000"

    result = runner.invoke(device_cmd.get_fake_tuple, [str(user_id), "upper_bound"])
    search_res = re.findall('\"(tid|data|num_data|added|correctness_hash)\": \"?([^:,\"]+)\"?', result.output)

    assert len(search_res) == 5

    column, ciphertext = next(pair for pair in search_res if pair[0] == "num_data")
    plaintext = decrypt_using_ope_hex(data[f"device_data:{column}"], ciphertext)
    assert plaintext == -959

    doc = search_tinydb_doc(device_cmd.path, 'users', Query().id == user_id)
    assert doc["integrity"]["device_data"]["num_data"]["upper_bound"] == 2
    assert doc["integrity"]["device_data"]["added"]["upper_bound"] == 2
    assert doc["integrity"]["device_data"]["data"]["upper_bound"] == 2
    assert doc["integrity"]["device_data"]["tid"]["upper_bound"] == 2

    result = runner.invoke(device_cmd.get_fake_tuple, [str(user_id), "lower_bound"])
    search_res = re.findall('\"(tid|data|num_data|added|correctness_hash)\": \"?([^:,\"]+)\"?', result.output)

    assert len(search_res) == 5

    column, ciphertext = next(pair for pair in search_res if pair[0] == "num_data")
    plaintext = decrypt_using_ope_hex(data[f"device_data:{column}"], ciphertext)
    assert plaintext == -980

    doc = search_tinydb_doc(device_cmd.path, 'users', Query().id == user_id)
    assert doc["integrity"]["device_data"]["num_data"]["lower_bound"] == 2
    assert doc["integrity"]["device_data"]["added"]["lower_bound"] == 2
    assert doc["integrity"]["device_data"]["data"]["lower_bound"] == 2
    assert doc["integrity"]["device_data"]["tid"]["lower_bound"] == 2


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_get_self_id(reset_tiny_db):
    device_id_doc = {"id": "23"}
    insert_into_tinydb(device_cmd.path, 'device', device_id_doc)
    assert device_cmd.get_self_id() == "23"


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_get_fake_tuple_info(runner, reset_tiny_db):
    user_id = 1

    payload_no_request = '{"user_id": 99}'
    payload_wrong_user = '{"user_id": 99, "request": "fake_tuple_info"}'
    payload = '{"user_id": 1, "request": "fake_tuple_info"}'

    data = {"id": user_id, "integrity": {"device_data": {
            "added": {"function_name": "triangle_wave",
                      "lower_bound": 12,
                      "upper_bound": 11,
                      "is_numeric": True},
            "num_data": {"function_name": "sawtooth_wave",
                         "lower_bound": 12,
                         "upper_bound": 11,
                         "is_numeric": True},
            "data": {"function_name": "square_wave",
                     "lower_bound": 12,
                     "upper_bound": 11,
                     "is_numeric": False}}}}

    result = runner.invoke(device_cmd.get_fake_tuple_info, [payload_no_request])
    assert result.output == ""

    with pytest.raises(Exception) as e:
        runner.invoke(device_cmd.get_fake_tuple_info, [payload_wrong_user])
        assert e.value.message == "No user with ID 99"

    with pytest.raises(Exception) as e:
        runner.invoke(device_cmd.get_fake_tuple_info, [payload])
        assert e.value.message == "Integrity data not initialized."

    insert_into_tinydb(device_cmd.path, 'users', data)

    result = runner.invoke(device_cmd.get_fake_tuple_info, [payload])

    expected = '{"device_data": {"added": {"function_name": "triangle_wave", "lower_bound": 12, "upper_bound": 11, "is_numeric": true}, "num_data": {"function_name": "sawtooth_wave", "lower_bound": 12, "upper_bound": 11, "is_numeric": true}, "data": {"function_name": "square_wave", "lower_bound": 12, "upper_bound": 11, "is_numeric": false}}}'

    assert expected in result.output
