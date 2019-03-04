import io
import json
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
from app.models.models import MQTTUser, User, Action, Device, DeviceType, Scene
from crypto_utils import check_correctness_hash, hex_to_fernet, hex_to_ope, decrypt_using_fernet_hex, \
    decrypt_using_ope_hex, decrypt_using_abe_serialized_key, blind_index, hex_to_key, encrypt_using_abe_serialized_key, pad_payload_attr, unpad_payload_attr, \
    unpad_row
from utils import json_string_with_bytes_to_dict, get_tinydb_table, search_tinydb_doc, insert_into_tinydb

cmd.path = '/tmp/keystore.json'

# NOTE: These values are necessary here, because global vars are not properly initialized when using Click Test runner
cmd.VERIFY_CERTS = False
cmd.MQTT_BROKER = "172.26.0.8"
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
def test_send_column_keys(runner, access_token, reset_tiny_db, bi_key, aa_public_key):
    device_id = "23"
    user_id = "1"
    key = "fcf064e7ea97ab828ba80578d255942e648c872d8d0c09a051bf5424640f2e68"
    result = runner.invoke(cmd.send_column_keys, [user_id, device_id])
    assert f"Keys for device {device_id} not present, please use:" in result.output

    device_data_doc = {
        "private_key": "dummy-value",
        "attr_list": ['1-23', '1-GUEST', '1'],
    }
    insert_into_tinydb(cmd.path, 'device_keys', {
        'device_id': device_id,
        'shared_key': key,
        "device_data:data": device_data_doc,
        "device:name": '4e7ed70343c0187f8d9acad60477e908ba23aeca0d8513399ce2c3c154e8d312',  # random
        "device:status": '688f7c16a252c66b042426416181e8112970d32aae120e1d365e898ae9433c6d',  # random
        "bi_key": '55b38a6c2575284fe511fbb4be114ef00162e6e7e3f10131f5365f77e1eb6bdb'  # random
    })
    insert_into_tinydb(cmd.path, "credentials", {"broker_id": "4", "broker_password": 'test_pass'})
    insert_into_tinydb(cmd.path, "aa_keys", {"public_key": aa_public_key})

    result = runner.invoke(cmd.send_column_keys, [user_id, device_id])
    assert "Data published" in result.output
    assert "RC and MID = (0, 1)" in result.output

    doc = search_tinydb_doc(cmd.path, 'device_keys', Query().device_id == device_id)
    assert "action:name" in doc
    assert "bi_key" in doc
    assert len(doc) == 11

    fernet_key = hex_to_fernet(doc["device:name"])
    assert isinstance(fernet_key, Fernet)
    cipher = hex_to_ope(doc["device_data:added"])
    assert isinstance(cipher, OPE)


def test_aa_retrieve_private_keys(runner, attr_auth_access_token_two):
    result = runner.invoke(cmd.attr_auth_retrieve_private_keys, ['--token', attr_auth_access_token_two])
    assert "\"success\": true" in result.output
    assert "\"private_keys\": " in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_get_device_data(runner, access_token, app_and_ctx, reset_tiny_db, col_keys, aa_public_key):
    device_id = 23
    device_name = "my_raspberry"
    user_id = "1"
    r = Mock()
    r.content = b'{\n  "device_data": [\n    {\n      "added": 2116580122, \n      "correctness_hash": "$2b$12$cHfLcwR4.ulBJXDMXMbJ2.JSAkD4OiHgr1kqw8u/m/tiZ4gqJwIWm", \n      "data": "eJyVVVtT4koQ/itUXnFrM8lct2ofVG4KKAiocDxlhZAgCssl4Wr538/0TE/w8exDYHrS0/P11193Pr2YeL9Kn971az6bTxKzfn2N51GWvb5qyxsf8yTzLkp6dxfNt4nZ/YeRixKTFyWlH+JrgwS+3uFghXZbsIsSF/rRmyzQNrwkVBsMvChY8Eq7C21wvSvRnRCGC19pD2LfCPgPbVDiw8VE7ygFl+v4UhtUusPgQwReRPVCahelMQqA4tuoAAs8pSq8dXzJMaL5MWd0WCkdNt8CJkSeUReXCjwCm/DAGo5xDGGOw702eW5jwT8vEpEY0xfIK+wwDGx2bQB9QIRIKmQuMJp09QDGoAwGKhAFbwEhkAHEE5+hq0nAHARcNETugW9gx4SXGIkCUp+74z6yqiBlIMbHG4oymjSLjIhhMXBq4A4jx2oBSJNpQJy4jFp839UFMpc+1g28jICERWZylO4ySALUqMzNYaEcrDwwBDVkDreRg0Q5GHUTigDOltG6sLghMFxpKeOoSrDEOU/fltdwAAxC2YRCVXBbGyAK8EuA4yMcgdyz77oXCmPa7pOIT6KibVWAe9N2BNkkCJLRgtDAukArADSl/v3SjX79f4cAoIUhAMAsv7ToI+WqGlpRQHxHgXQtzgiWieMoAV6ABxE4oXM7LwA0ZGKkR7BJCwYD14TYaEY0UEXh1AI15sSmdzT5kR9B+LeJQiLmcRf6AebKlRtYoZUGXGjUyO1aIF5WkIItyQthmsHCvtEJapJOUeBr+z/ENjC6cDvAHAjAANGJ2kxXf50qBGSOQtvoCisY2HFgleefEUFJqRv4rpNFoQKCMzdwk8ZoNcTOldgJxgCVU3e5DUVtQwB9spAZ/6YOMxbMcEf9MDwCgQw8jvAQiJGUX5AeYggzPgQqDScfY+6TQhxKH78mmL9tJmK5l/ji/AEhCstjVemStlwQxI00mg+MdIJwzBstnT9m0l7JHPRvrLqUTGdIN5dxbhnpcQsPpzB2hRENOYtmtZzPYmgRL8s3v0A6JfKjPqj2+iUCaonyfDMbb0E7Wi6Fk2d6Kw6MzqL51AVotC+vX3uNywDOLrJi//PFu2zVX7SpEb147ftKFYwAjJtHWL54lT1drvrzkI3DRqtVIfktH6nL379fPPC6nq3ekk0/OeTW+/R0F07WYSfZtSa7J07fD+/rbust+rhlD9nwpp2V48Om2+zRUXY92+Z5FFX7tdsRz1unpL0p33XvyGOjdvkn+SjTYXxVmzWTqPvzqtsZLdN1tTk4PN6oupw9V1fdfXQ1zqbD8UQtk4fBoDVrRL37oNfsjN4fyttp+LGoiuOmPdq19t15+vRRJqeb1WOm/Oe3n5W72nsYiRUbdIfrcBnz6bNYdNed3aix/Jk9l9vrCm1tK8te73H1UT1MxvNrVbthdXJaXXYbD7vK07xBoyRvdmv3b+u34/BQmfLgdpItTknreSX41XTg++xh+bZftOPGccv3N/XdR1y7pek72Yd/5CHeq9H46bScBY8dNZ8v1VVztWSHzuIYn5r5rt+7GvYX7eGmUU00baeKVDKvx+V6S+bdaBnM97oCX1DPyWyaZLkraZySVEWJ5FLGJKVszFOaTniUBqng4TiQMqRpIAhLZSAm/jikk4SrULFwQoWS1Pv6+g8xAFPq", \n      "device_id": 23, \n      "id": 6, \n      "num_data": 464064, \n      "tid": "gAAAAABcc5_jPEABPUBv4E-VWpazMSRF-5z6JDu6SMSDpLDUslW-hLdIdGeILVoE_7mSoHr-RZzU7KojN6MnI14DNen5Ojjgxw==", \n      "tid_bi": "19b0ac102511621a04272dc74ded56124ec487e4068e32f5274cbf04e7edbd1e"\n    }, \n    {\n      "added": 2244039737, \n      "correctness_hash": "$2b$12$wLVpRu1igPcIS1k1YqQAeetu7seKSxArKLdNqk8aOS68D2Qn9M.4K", \n      "data": "eJyVVdtS4zgQ/ZVUXmEKSZYsaarmIYlJCIQKFydcli3KdpyrMwnYDgSKfx91S8ryuPMQsFqtVp/Tp1ufzYw2fzY+m53nalFMcvx+fs6KpCyfn82qme6rvGweN4x1lxR1jtZ/BD1uCHXckOFxg1JmPswCjJoYA2N2ocyPEm0WAVhxZQ5o48ulsRpfBf4EtqnZkWYltbdqF5tSbkzc+cBprd0+OOKCGqsyYULzP5T+NJE2Zgg5mEhh6GJT46ogd2KsXNkdvEwpsHKbIcDT0qKS1GEAdwygfSTpwkOOmIQ5xgObKqXCbOJVxH5gUHNCSgddSBcZLBLiSJdMKBw8ZDR012Ek2MIPLh1D6GQJ9tHBDHkjecAIDxwrwAiy7TOjBBIwQZW2gJBnJEM4VjAjKDr/ziCFKgrrC+cRBF6DZ6T311Ykts7C/oRweQEaUAwclD4R4lhlLjugFaIrpzUAI7g9pKW/jHrs4TeKnZi4hQd0SOJSFPTAALPaAU4grqXY1wIlBldaAWnLISqK+wprmxwYbO2VKwvKi/jaUUasCbIGDgT3ztQ7I19OnJgENhOAsqSFh4JTJ1gsFJZDEJ8z8Y2n9KHPiMvCll56iR6aUf/7Zdq9839HAdd2FFitEHvVQfmoPub05qqOeiC+HbXNJPRt5loc+ghniFOCLWXo2eEeOQ6fAxmgSkgIroS2wtNeflgvatHtER79wYK/xYmZYwXtH2yE4JvK+Xep2cr60mGJsKKMemEzh0/YBO1oY366EFtvQGgnk4spvHyxgnYEUi8bLzYQMAC2iLd/DRkuOUx54qeqChx0bFaHHhvVjR1Yw1QCoMKNCbApr087l7xErBgDp3DG/JZ0Xc384HUNxJxYA8ewm/pYCGxZ6h4GHLbqIHmXjZWC+GbBGRL6thSHtnGDTblXQflBTt1AhOxC93ZA7rbwoQUfaj92/YOCQ9F2pbCHoLJwCKTD/UMAd0vXDLavUeKeOxybHoYVS+gGMLGRlB+TwqYonRSlb5DDW2PpdYQDcEAR0v9Es90UiwxapVlWrz9BOg36ozc6vY0bFNSSVNXrIq1BO0YuB6cm9ljGUGdJMfMBzi5bnefbsxaDs+vyYP98arYGvSezNBCempfD6BQWDBb9MXw+Ndd1dhXFl8tRP169lf2Len2yrWe/fj01wauz2M7z1zh/r6x3sa06rXmPZqP2VO1TcroubnhOZTftB3kvbr8eHW37bzfXU7paXkS7ySAdLpbv9+POGxt0TsI8v6TDwcO0VfXbFzm9oaTf6X1Uv8eEbEkUXuRi0ZtNWmf7aMXq4W7cP9Mni8713Xy4eJlvy2jz+juZ8KRbnS7XUgZ7+nY5G8nptuL9+ma8jB+j+XAV7+Nx93R5xseji3r8yNP66Lqev5dFVbS2LZUehZvL/L7bHqezl+mOKMn1OtjkN7sg+728O0rbeStL9tOsGJUqOnloLwpWp5MyWm+7PbbZxPvecCeGrend+XZ4NdpdnT+Qq4Lr99kiFsOX+Wq1ii/K6P4uuv3YvUxOosdld9gO+2dXBRnefsySwWn3dhqPxvWAloIF63rw0Rvc3q/j8zQKH642u7WakfHKVOAL6jlZzPKy8iUVeS6kTrWYJoryNNMsy1KapgkjlPGMJeFEsYznMk9UEGgqE5mIiVbJJMsYyfPm19cfUsFWNQ==", \n      "device_id": 23, \n      "id": 8, \n      "num_data": 466263, \n      "tid": "gAAAAABcc5_jcRdS6byYUE52rJ2Hv4rgvdf73XE6vh1_mColel-lRltMLJE9DolpZyuaE88B-44FO7CpEdEzwny_cR6VxdazKQ==", \n      "tid_bi": "8cca81860609303ae65ab3ee804a7c0dc2a783eed2c39ee27ee435cfc639825c"\n    }, \n    {\n      "added": 2328646538, \n      "correctness_hash": "$2b$12$WtybMtflI4FZX32/J/ydOOn5aXbz5um1I9O2VfB2T2YgrLnlIyXYm", \n      "data": "eJyVVVtT4koQ/isUr7hFZpLMZav2IWq4KIqCyOV4igohwXhAlEQXsPzvm+7pieXb2YdAZqan++uvv+581GNW/1n7qJ/Ni2y9TPB9Po/XUZ7P5+WqvjgUSV4/qZW779H6LcHdf3x2UvPVSU055b9X/pdrWb4LcVJjjoYfWa7g8csF5+UPK7cVvsCW457UPE23y1u+C5vgtrwk0Qx8l6ZCk38JFnhS2svyREI0pmxICCAZvHgGmYR/z+BgnFkgAA2OEAhGUAQI4AMoSOUrFCBCeBAA7BGawCzBAxiz0kb55sEofpU3JKUdQqqlgeQRGZgY+gZT/i0uwMIUARr404psgDDIQGoyxZQxMQDgqa+qMMepSILsSldS0RFcqnwa+rSBh7C4YZk5yJVrs5CGJ8zUlFLYc03EOsoSxU3dIKQnjV+gAChVrqkSoMXrPiNG0aO0bHHLDnMoIngyDPmGSXBhKgoVAnDK5AIusag2f9jU2np0SL64Aizg0OcWBvAD1QU5+IJKiVX2SDRG2IqOGeJiVsjCxIYHy8ip1rCAFFDCPjmQhAChAD2IEqlHQTiUJiAEahCXJIfqG0UgAyRZ0GWQKjxQPys4pFZagVma3H8/y1Y/+79jABtYGboNbba/DNmOiYFsYhMCPlU1t0ddBMSgvjW1PrfCNXXzKpVrIhiyNwQp84LXadOGNQq0/GB/Aw5mcjxgkuwHd/86W9fQqGh0YCmoI5UmHWCTeYRe6YoWVXW4b9SIPQy5ympimDHgktY4taRHREp7qkkCopoRnhmAAM6manJ9+etkISmfdImDSNIEZq7FS+pBFTmUyDfoRtjC1t2lHfVFhG+bSlZDihMLkhi2SvbsiFc0c31uJ7egYVXFlnbhmaoI+liYzqcvD1hp+sZgtfhXh9iuV9W4kFbhNJgND6gun+YNPcgBfhTwO8CpLtIKgxMm24C2gjh/pW11qq+yU03ZTH3b2UAXmHk0KCt4shptwkxAYF7aTzAOGpdKRtygYNiXYF626yyGBqnnxe4nyKbGfrRH4fCuxkApUVHsssUb6KaUSmVUx86KOWosWq+sg85VcDYfdgIOdzd5tf/xUA967YdyWWJ5qF/1z0NYcFh07+H1oX7IZjehmm510Qwu2tHI6TQG++DXr4c6WJ1lL4/J7i7ZF8Z6eHpcFYvg6dTbjUaFTg9CTRuPx2zaak+8gq/3m3tfJevxpDFJeOt4277gw+Utzy7Flsd++haJidu8z8fd16g3OndY0XcPZ9IRbHM3HVymzWOY/B4vx/3g9jDqRa1uGi5m0WB4HG+9th6NRivvOYwa+jG4vg6Vmi2GUk2z9Sx8TZudQUs/i0N8MVytgg1vZ/lb48j0ZPB8k91ed9cvfZmMny6eT4/94i11Ns3ubTsIBr1J46aVd4qRTvRTvu0d+sdje7AMVdRPL/bP7/vR6c7dBM2ZM14+TbP8srjLZu9T7/wxvLwIG9fLVtzr78Sscfea9bp6MWmeh79z2QnFtT/Y34134eR18nqe620gnoPwcHl1czwfZp1u1tfLTd+X6zgPN4U+zCbtp8fV0/tVuJ34wX9xWYFPqOcyWyV5YUsqhGZeGqtUp4lc+HHkOpEQro5FGqVCxFrIJI28xIkWiSOFXz4pXyQJS5KFZklc//z8A71NUpA=", \n      "device_id": 23, \n      "id": 4, \n      "num_data": 471232, \n      "tid": "gAAAAABcc5_jbq_4CrB8m_p4bjLj8Ivo9jrE02oTu_U4oKWzaZd8ghcUvrIsqrs2GZoIyQvD8JF3RqKpPZ-rogejv723gyo-2A==", \n      "tid_bi": "e7d546fbae9151090d66a378664eaf3450b6ee30a2f7df495343f514497b4b12"\n    }, \n    {\n      "added": 2893054513, \n      "correctness_hash": "$2b$12$fKkQzkjg9mh21ACcNdk8/ulKruhf1Qd5JVmOPz1iUszMPGB6qt7a6", \n      "data": "eJyVVdty4jgQ/RWK12QKSbZuUzUPhDvDLdwCbLYoDIZAIAQwTCCVf191S4KZt50Hly2p1d2n+/TxZ3pK099Tn+ncOFmuZzF+j8fT9eRwGI/NKh2dk/iQvk+Z3dNkfYxx9x9O71Nc3aeUNg+5Twlp1sI8oXnMWpozDWfGjlJzKLlZMFhwt0MZLElgDSW1zqSGY7zF7Akl5gbEE8a/Mk+o3SmlJhIHM/PWylpIcE1Ce1dw65VL64JS8GEsZWgfuA0+Obc40CVGBUuMAuaUCOsIMw9xB6wJtXDBhuMGYA6sb0qk3YUgHDadb6gFpgjpCV8KBVUyb2EstLTWeIDmlPjgHh94FNCC0JfR94PdQmL40IMAS0asD+lB4AdUHPqHOUPTZGAzsaADm0UIb2G9S+HuQ20BxDWEch2hNHQniFf53IkFDlih7DaRwFMD8gP4EEtdaYKMIJiLtpABOiAE57b03FID8rH0IM4MdrWDjc1hjqiBDeWYGFoWAnKAoOjVD7X34MH8sEpC+WwCVyLoLXKHOWgWOPV0UK4cnl6YOndRLA/+hKkdu4jnGwTHnivHD+J5pt2JQH/K7WJJhXC9wBIBYKSXcCk59OzfLzPkuf8rAFhpN+SQuvRurTPvG8MCbflv3cbS+MRt9UIHGQtFfUEldWAQFRQHiaPdtCtPXmYvQsegc0AdyA/eOGKQI7X4zgiQfmPB3yK1BNGuo9oFD6/zQezCDrd0u9wpExJcOLGEWik3NZirutUQlQbpHnrtE16JuB9/+jsFrJaSP6FarO9/DRb1QvkWUqe6MvCCiNyEziK1qVNQVFNHZgSBwhx4arou4zQTdpMRNAMctwlSbvC5G24vydINJFKM2m8QdKBf6AVMuv8HChlURDpCaG9hVUhf8XllxV/XdfaI/wddPWOCKAOhVzHubeTtj3dlr9BXuXVaY90IWwXt6QRxtWsm/qNu06tdfgiIO8T+34nl0LaKKPn+f0Gc6ojrPxL4BGGQucwTBnCgcDvPgt54875dL6cwJ+lDsv8O7EnRb6VeodNNUSDMJEn2y+gI9DGMuRqlccCmDKk2WS+8g3I9mxt3ylkGdzeH6/7nczpbKz2bpUnqOV1v5guwYLCo9OHzOb1kRVENd8eHQ6F1/Oi0m+ViPpv98eM5DVa55ftLvO/GH4m11tXaZZLv7hZPhV2uF3YWuid5Ju4N95W+2F+2x1Y/3yg3Grr+troMMip4/TWtnndkFG3aE/qYoZ18Z0bafK3qLf12GVbYQrMq2fXf8seglxzWD9Vl4TWptTJNdTxN+ifx2k1GL490mOkVM5kjXQ2Ws/fa/FhloxfSpg8PpdLHpN7az/K5ke7XCoviNqkXaueCvmSPMhvv430u+tU+vTQK5WGxGpFFZtXqbLJP6rHyumXln4v8QN+dLnG2vHqq8c5mcKg04ly71SmtTjPauSOi+VEfbofycqqxl9Wg9vQ636jzrrJgd9VN8Y3NtwdSeJTLki6Kn/2kXWuWguFdJRzEWTrqJr1CdxSsFodauxH3j8tucZp/0HEyHM569cO5nF+ty+yuWV4Py4XKslteCD4vdui5okwHvqCfs+UiPiS+pSHTjERcR1GkpAqnSoTzUEZzLbj5DCYxnSkWSLOikyjiEyIDOpkRReJQs5mM0l9f/wHCxE7b", \n      "device_id": 23, \n      "id": 12, \n      "num_data": 468360, \n      "tid": "gAAAAABcc5_jp9eHuXaD1N2Srcyt51rOpfKlUNye-NTsj9c2K-ZKrpgoKYt59mYdTXrNzQPDwdDtXogFtBXRf_d21RzWNBBZ2Q==", \n      "tid_bi": "c4dedc6cfb2d4fa1d298ccb7a1b3309a93cd241e23b04e33b11deef1e8d1451d"\n    }, \n    {\n      "added": -1068054143, \n      "correctness_hash": "$2b$12$o5DZEBEE2IzNez1d0Qj2Y.iqTzFpeo3CTfcOGkgSXiMw.AYwEf7fW", \n      "data": "eJyVVdly4joQ/RWKVzKFJGvzVM0DWxIyhISwJMPNLcrYZt9tEiCVf79uqeXk8c4DYAmp+3Sf08cfxZAWfxY+irVROl9FsXkejcJVkCSjUbYqjs9pnBSvCtnuW7A6xmb3H0GvCkJfFXT2oURdFVS2QamXPXDYybZF9qCyX5n9q7M/dPYL18xxSpm9LH1YZF9c2btwTZtNOC+zTQZ3IAA8UAlfBLayLy1gxTEMMakZpoCAGu57cIbaQDxbCGb/9CEBscB4dt+HWihg0vYw3M4DK/FtoXEB9UDlUiJgDQUyZneUnwOG0IxgTuawwkEokRJhbwjP3lJflRj0wqaCvgjuatcWupLYThuJY144YqAJRGWaBgwZdmwZrhPEFm3rw/yGBJLF1BgSeqcIVuOogu5CePhwjcF9HzkQTgzS9cYCUEj6F2VQCUA1uCETZNWe6xbBOMACxwwGD7NxoTvAIXwURjC5tJ+nIphKoTiNGKG12kOefILgoBEKWwqpoDkARCk8aVssbGEQDLD72HJDMsrZqN6zLAmBwEz9IAeLTmNgQrFK7iMygOq7v3L9G22hmAz7ZgAFxhSYVeVUwy7PpUtwHCy3FAcoC/zvZzbltf/rABBQaAxj8PmoIBgOSK6cLRCsxJgGd/PuIYMcTxiBWiq0Pc+RcITrJsGSiETnrJh2MhtBoTKEmyCAJakt8GwqpD+Y97elghLy4bWVuZmCzEAv0O4kAfZhEDGnF+dERgQMh84anYdhrQkhdjO70nJmhZP7p6lKIwSTmVs24Q6Uamvd/XWx4IhQrJl0yKccvzqXr7M0IAiQc2cVuUUw5rh06oVzsMMVMghtMrainWW64QIIytm4sbmcS+E0TfGNklsyYDB9Us5lGMFWmmuGROcK0lXgBkX63zps0vFvI+rj20E6cGgH1tctKHRM0LhxC+dl1mEkUsb1t1HM3R41bBvwzTwU4oa8pptukow/IR3GJJVTDs/fNhSHyHcT495Thj5ouCkJXw+Sfslmt13NQxiTYpIefoJ4CvTHTb/R7RUo6CVI08N8fAT1ZILJDxXNfIXMKC1YTV2A2/tKbdS9rTC4u07y/Y/XYqV185otsza9Fu8f6g1YMFg0B/D4WlzGtWC8jJuL+lL75f2uM5jdHSu/fr0W4VRtvpvFh158Su3p5r6cnN/Uno7D/uTuMggmN/ql9KZE+/Deng/1OL2/vPCkK5e8sr4bNkSdv6d9viJpnZ9uypcmG5/LQbwq1c6t6noznTTbsaidD6J7enzTp83eq1OuS+0p7T3rNK3SXb/Rbq+vkzAkhLw8zmK/cdpUkwd2P02eZtFifQzHwb7avZXjBaOVTqkftJfvnldplTv3l872eVO+eeLzWmfW3tx1N+N9aeJtA95bXeT8or1FLB8f1GG1bHV64WzuxxcSyXI5Krcq3UOz97v0nq76D40hva3Whzzi1T/Dyt12uNuud8vG4vgkO42ZeuNqOg1XL5Ok2jp2WJlteJO+XHx523xsJpPq9vfDvd8ZeIM/60VlO6kOTnRzrWu15+dr2dqej/Pr+THUs5K8XPqlyexSClu96p+MgU/gM5pP4yR1lMqIyomUUcRCyZgXEDmmZBKLwAu5FFFEyFgEE06V5wd+pFUw0XEUM0Kz89Qnovj5+R+JE1C+", \n      "device_id": 23, \n      "id": 26, \n      "num_data": -1338610833, \n      "tid": "gAAAAABcem_Lh0-Angt4oGNlL8KiF9a3rDvT_TB3gn6RD_W_ladmyIofV20hQmhlThAZwKeqPAw-XaEFZuDcrmVHhqPx7bNjQQ==", \n      "tid_bi": "8b8877ba600293e3b19d263d27d3ebab1a2ed49b452f5e77622c18dd7adb3279"\n    }\n  ], \n  "success": true\n}\n'
    fake_tuple_info = {
        "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
        "integrity": {
                'device_data': {
                    'added': {'seed': 1, 'lower_bound': 2, 'upper_bound': 2, "type": "OPE"},
                    'num_data': {'seed': 2, 'lower_bound': 2, 'upper_bound': 2, "type": "OPE"},
                    'data': {'seed': 3, 'lower_bound': 2, 'upper_bound': 2, "type": "ABE"},
                    'tid': {'lower_bound': 2, 'upper_bound': 2, "type": "Fernet"}
                }
            }
        }
    cmd.fake_tuple_data = json.loads(device_cmd.encrypt_fake_tuple_info(fake_tuple_info))

    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    insert_into_tinydb(cmd.path, 'aa_keys', {"public_key": aa_public_key})

    app, ctx = app_and_ctx
    with app.app_context():
        with mock.patch('requests.get', return_value=r):
            with mock.patch('client.user.commands._get_fake_tuple_data') as _get_fake_tuple_data:
                result = runner.invoke(cmd.get_device_data, [user_id, str(device_id), device_name, '--token', access_token])
                assert result.exit_code != 1, "Attribute padded incorrectly."
                assert "Data Integrity satisfied." in result.output
                assert "failed correctness hash test!" not in result.output

                r.content = b'{\n  "device_data": [\n    {\n      "added": 2116580122, \n      "correctness_hash": "$2b$12$GeqMXIMKiE6rOF9YVL2TO.S7vf7Jc4RP8MXgL9d0kgIJfthUQjxM6", \n      "data": "eJyVVVtT4koQ/itUXnFrM8lct2ofVG4KKAiocDxlhZAgCssl4Wr538/0TE/w8exDYHrS0/P11193Pr2YeL9Kn971az6bTxKzfn2N51GWvb5qyxsf8yTzLkp6dxfNt4nZ/YeRixKTFyWlH+JrgwS+3uFghXZbsIsSF/rRmyzQNrwkVBsMvChY8Eq7C21wvSvRnRCGC19pD2LfCPgPbVDiw8VE7ygFl+v4UhtUusPgQwReRPVCahelMQqA4tuoAAs8pSq8dXzJMaL5MWd0WCkdNt8CJkSeUReXCjwCm/DAGo5xDGGOw702eW5jwT8vEpEY0xfIK+wwDGx2bQB9QIRIKmQuMJp09QDGoAwGKhAFbwEhkAHEE5+hq0nAHARcNETugW9gx4SXGIkCUp+74z6yqiBlIMbHG4oymjSLjIhhMXBq4A4jx2oBSJNpQJy4jFp839UFMpc+1g28jICERWZylO4ySALUqMzNYaEcrDwwBDVkDreRg0Q5GHUTigDOltG6sLghMFxpKeOoSrDEOU/fltdwAAxC2YRCVXBbGyAK8EuA4yMcgdyz77oXCmPa7pOIT6KibVWAe9N2BNkkCJLRgtDAukArADSl/v3SjX79f4cAoIUhAMAsv7ToI+WqGlpRQHxHgXQtzgiWieMoAV6ABxE4oXM7LwA0ZGKkR7BJCwYD14TYaEY0UEXh1AI15sSmdzT5kR9B+LeJQiLmcRf6AebKlRtYoZUGXGjUyO1aIF5WkIItyQthmsHCvtEJapJOUeBr+z/ENjC6cDvAHAjAANGJ2kxXf50qBGSOQtvoCisY2HFgleefEUFJqRv4rpNFoQKCMzdwk8ZoNcTOldgJxgCVU3e5DUVtQwB9spAZ/6YOMxbMcEf9MDwCgQw8jvAQiJGUX5AeYggzPgQqDScfY+6TQhxKH78mmL9tJmK5l/ji/AEhCstjVemStlwQxI00mg+MdIJwzBstnT9m0l7JHPRvrLqUTGdIN5dxbhnpcQsPpzB2hRENOYtmtZzPYmgRL8s3v0A6JfKjPqj2+iUCaonyfDMbb0E7Wi6Fk2d6Kw6MzqL51AVotC+vX3uNywDOLrJi//PFu2zVX7SpEb147ftKFYwAjJtHWL54lT1drvrzkI3DRqtVIfktH6nL379fPPC6nq3ekk0/OeTW+/R0F07WYSfZtSa7J07fD+/rbust+rhlD9nwpp2V48Om2+zRUXY92+Z5FFX7tdsRz1unpL0p33XvyGOjdvkn+SjTYXxVmzWTqPvzqtsZLdN1tTk4PN6oupw9V1fdfXQ1zqbD8UQtk4fBoDVrRL37oNfsjN4fyttp+LGoiuOmPdq19t15+vRRJqeb1WOm/Oe3n5W72nsYiRUbdIfrcBnz6bNYdNed3aix/Jk9l9vrCm1tK8te73H1UT1MxvNrVbthdXJaXXYbD7vK07xBoyRvdmv3b+u34/BQmfLgdpItTknreSX41XTg++xh+bZftOPGccv3N/XdR1y7pek72Yd/5CHeq9H46bScBY8dNZ8v1VVztWSHzuIYn5r5rt+7GvYX7eGmUU00baeKVDKvx+V6S+bdaBnM97oCX1DPyWyaZLkraZySVEWJ5FLGJKVszFOaTniUBqng4TiQMqRpIAhLZSAm/jikk4SrULFwQoWS1Pv6+g8xAFPq", \n      "device_id": 23, \n      "id": 6, \n      "num_data": 464064, \n      "tid": "gAAAAABcc5_jPEABPUBv4E-VWpazMSRF-5z6JDu6SMSDpLDUslW-hLdIdGeILVoE_7mSoHr-RZzU7KojN6MnI14DNen5Ojjgxw==", \n      "tid_bi": "19b0ac102511621a04272dc74ded56124ec487e4068e32f5274cbf04e7edbd1e"\n    }, \n    {\n      "added": 2244039737, \n      "correctness_hash": "$2b$12$wLVpRu1igPcIS1k1YqQAeetu7seKSxArKLdNqk8aOS68D2Qn9M.4K", \n      "data": "eJyVVdtS4zgQ/ZVUXmEKSZYsaarmIYlJCIQKFydcli3KdpyrMwnYDgSKfx91S8ryuPMQsFqtVp/Tp1ufzYw2fzY+m53nalFMcvx+fs6KpCyfn82qme6rvGweN4x1lxR1jtZ/BD1uCHXckOFxg1JmPswCjJoYA2N2ocyPEm0WAVhxZQ5o48ulsRpfBf4EtqnZkWYltbdqF5tSbkzc+cBprd0+OOKCGqsyYULzP5T+NJE2Zgg5mEhh6GJT46ogd2KsXNkdvEwpsHKbIcDT0qKS1GEAdwygfSTpwkOOmIQ5xgObKqXCbOJVxH5gUHNCSgddSBcZLBLiSJdMKBw8ZDR012Ek2MIPLh1D6GQJ9tHBDHkjecAIDxwrwAiy7TOjBBIwQZW2gJBnJEM4VjAjKDr/ziCFKgrrC+cRBF6DZ6T311Ykts7C/oRweQEaUAwclD4R4lhlLjugFaIrpzUAI7g9pKW/jHrs4TeKnZi4hQd0SOJSFPTAALPaAU4grqXY1wIlBldaAWnLISqK+wprmxwYbO2VKwvKi/jaUUasCbIGDgT3ztQ7I19OnJgENhOAsqSFh4JTJ1gsFJZDEJ8z8Y2n9KHPiMvCll56iR6aUf/7Zdq9839HAdd2FFitEHvVQfmoPub05qqOeiC+HbXNJPRt5loc+ghniFOCLWXo2eEeOQ6fAxmgSkgIroS2wtNeflgvatHtER79wYK/xYmZYwXtH2yE4JvK+Xep2cr60mGJsKKMemEzh0/YBO1oY366EFtvQGgnk4spvHyxgnYEUi8bLzYQMAC2iLd/DRkuOUx54qeqChx0bFaHHhvVjR1Yw1QCoMKNCbApr087l7xErBgDp3DG/JZ0Xc384HUNxJxYA8ewm/pYCGxZ6h4GHLbqIHmXjZWC+GbBGRL6thSHtnGDTblXQflBTt1AhOxC93ZA7rbwoQUfaj92/YOCQ9F2pbCHoLJwCKTD/UMAd0vXDLavUeKeOxybHoYVS+gGMLGRlB+TwqYonRSlb5DDW2PpdYQDcEAR0v9Es90UiwxapVlWrz9BOg36ozc6vY0bFNSSVNXrIq1BO0YuB6cm9ljGUGdJMfMBzi5bnefbsxaDs+vyYP98arYGvSezNBCempfD6BQWDBb9MXw+Ndd1dhXFl8tRP169lf2Len2yrWe/fj01wauz2M7z1zh/r6x3sa06rXmPZqP2VO1TcroubnhOZTftB3kvbr8eHW37bzfXU7paXkS7ySAdLpbv9+POGxt0TsI8v6TDwcO0VfXbFzm9oaTf6X1Uv8eEbEkUXuRi0ZtNWmf7aMXq4W7cP9Mni8713Xy4eJlvy2jz+juZ8KRbnS7XUgZ7+nY5G8nptuL9+ma8jB+j+XAV7+Nx93R5xseji3r8yNP66Lqev5dFVbS2LZUehZvL/L7bHqezl+mOKMn1OtjkN7sg+728O0rbeStL9tOsGJUqOnloLwpWp5MyWm+7PbbZxPvecCeGrend+XZ4NdpdnT+Qq4Lr99kiFsOX+Wq1ii/K6P4uuv3YvUxOosdld9gO+2dXBRnefsySwWn3dhqPxvWAloIF63rw0Rvc3q/j8zQKH642u7WakfHKVOAL6jlZzPKy8iUVeS6kTrWYJoryNNMsy1KapgkjlPGMJeFEsYznMk9UEGgqE5mIiVbJJMsYyfPm19cfUsFWNQ==", \n      "device_id": 23, \n      "id": 8, \n      "num_data": 466263, \n      "tid": "gAAAAABcc5_jcRdS6byYUE52rJ2Hv4rgvdf73XE6vh1_mColel-lRltMLJE9DolpZyuaE88B-44FO7CpEdEzwny_cR6VxdazKQ==", \n      "tid_bi": "8cca81860609303ae65ab3ee804a7c0dc2a783eed2c39ee27ee435cfc639825c"\n    }, \n    {\n      "added": 2328646538, \n      "correctness_hash": "$2b$12$WtybMtflI4FZX32/J/ydOOn5aXbz5um1I9O2VfB2T2YgrLnlIyXYm", \n      "data": "eJyVVVtT4koQ/isUr7hFZpLMZav2IWq4KIqCyOV4igohwXhAlEQXsPzvm+7pieXb2YdAZqan++uvv+581GNW/1n7qJ/Ni2y9TPB9Po/XUZ7P5+WqvjgUSV4/qZW779H6LcHdf3x2UvPVSU055b9X/pdrWb4LcVJjjoYfWa7g8csF5+UPK7cVvsCW457UPE23y1u+C5vgtrwk0Qx8l6ZCk38JFnhS2svyREI0pmxICCAZvHgGmYR/z+BgnFkgAA2OEAhGUAQI4AMoSOUrFCBCeBAA7BGawCzBAxiz0kb55sEofpU3JKUdQqqlgeQRGZgY+gZT/i0uwMIUARr404psgDDIQGoyxZQxMQDgqa+qMMepSILsSldS0RFcqnwa+rSBh7C4YZk5yJVrs5CGJ8zUlFLYc03EOsoSxU3dIKQnjV+gAChVrqkSoMXrPiNG0aO0bHHLDnMoIngyDPmGSXBhKgoVAnDK5AIusag2f9jU2np0SL64Aizg0OcWBvAD1QU5+IJKiVX2SDRG2IqOGeJiVsjCxIYHy8ip1rCAFFDCPjmQhAChAD2IEqlHQTiUJiAEahCXJIfqG0UgAyRZ0GWQKjxQPys4pFZagVma3H8/y1Y/+79jABtYGboNbba/DNmOiYFsYhMCPlU1t0ddBMSgvjW1PrfCNXXzKpVrIhiyNwQp84LXadOGNQq0/GB/Aw5mcjxgkuwHd/86W9fQqGh0YCmoI5UmHWCTeYRe6YoWVXW4b9SIPQy5ympimDHgktY4taRHREp7qkkCopoRnhmAAM6manJ9+etkISmfdImDSNIEZq7FS+pBFTmUyDfoRtjC1t2lHfVFhG+bSlZDihMLkhi2SvbsiFc0c31uJ7egYVXFlnbhmaoI+liYzqcvD1hp+sZgtfhXh9iuV9W4kFbhNJgND6gun+YNPcgBfhTwO8CpLtIKgxMm24C2gjh/pW11qq+yU03ZTH3b2UAXmHk0KCt4shptwkxAYF7aTzAOGpdKRtygYNiXYF626yyGBqnnxe4nyKbGfrRH4fCuxkApUVHsssUb6KaUSmVUx86KOWosWq+sg85VcDYfdgIOdzd5tf/xUA967YdyWWJ5qF/1z0NYcFh07+H1oX7IZjehmm510Qwu2tHI6TQG++DXr4c6WJ1lL4/J7i7ZF8Z6eHpcFYvg6dTbjUaFTg9CTRuPx2zaak+8gq/3m3tfJevxpDFJeOt4277gw+Utzy7Flsd++haJidu8z8fd16g3OndY0XcPZ9IRbHM3HVymzWOY/B4vx/3g9jDqRa1uGi5m0WB4HG+9th6NRivvOYwa+jG4vg6Vmi2GUk2z9Sx8TZudQUs/i0N8MVytgg1vZ/lb48j0ZPB8k91ed9cvfZmMny6eT4/94i11Ns3ubTsIBr1J46aVd4qRTvRTvu0d+sdje7AMVdRPL/bP7/vR6c7dBM2ZM14+TbP8srjLZu9T7/wxvLwIG9fLVtzr78Sscfea9bp6MWmeh79z2QnFtT/Y34134eR18nqe620gnoPwcHl1czwfZp1u1tfLTd+X6zgPN4U+zCbtp8fV0/tVuJ34wX9xWYFPqOcyWyV5YUsqhGZeGqtUp4lc+HHkOpEQro5FGqVCxFrIJI28xIkWiSOFXz4pXyQJS5KFZklc//z8A71NUpA=", \n      "device_id": 23, \n      "id": 4, \n      "num_data": 471232, \n      "tid": "gAAAAABcc5_jbq_4CrB8m_p4bjLj8Ivo9jrE02oTu_U4oKWzaZd8ghcUvrIsqrs2GZoIyQvD8JF3RqKpPZ-rogejv723gyo-2A==", \n      "tid_bi": "e7d546fbae9151090d66a378664eaf3450b6ee30a2f7df495343f514497b4b12"\n    }, \n    {\n      "added": 2893054513, \n      "correctness_hash": "$2b$12$fKkQzkjg9mh21ACcNdk8/ulKruhf1Qd5JVmOPz1iUszMPGB6qt7a6", \n      "data": "eJyVVdty4jgQ/RWK12QKSbZuUzUPhDvDLdwCbLYoDIZAIAQwTCCVf191S4KZt50Hly2p1d2n+/TxZ3pK099Tn+ncOFmuZzF+j8fT9eRwGI/NKh2dk/iQvk+Z3dNkfYxx9x9O71Nc3aeUNg+5Twlp1sI8oXnMWpozDWfGjlJzKLlZMFhwt0MZLElgDSW1zqSGY7zF7Akl5gbEE8a/Mk+o3SmlJhIHM/PWylpIcE1Ce1dw65VL64JS8GEsZWgfuA0+Obc40CVGBUuMAuaUCOsIMw9xB6wJtXDBhuMGYA6sb0qk3YUgHDadb6gFpgjpCV8KBVUyb2EstLTWeIDmlPjgHh94FNCC0JfR94PdQmL40IMAS0asD+lB4AdUHPqHOUPTZGAzsaADm0UIb2G9S+HuQ20BxDWEch2hNHQniFf53IkFDlih7DaRwFMD8gP4EEtdaYKMIJiLtpABOiAE57b03FID8rH0IM4MdrWDjc1hjqiBDeWYGFoWAnKAoOjVD7X34MH8sEpC+WwCVyLoLXKHOWgWOPV0UK4cnl6YOndRLA/+hKkdu4jnGwTHnivHD+J5pt2JQH/K7WJJhXC9wBIBYKSXcCk59OzfLzPkuf8rAFhpN+SQuvRurTPvG8MCbflv3cbS+MRt9UIHGQtFfUEldWAQFRQHiaPdtCtPXmYvQsegc0AdyA/eOGKQI7X4zgiQfmPB3yK1BNGuo9oFD6/zQezCDrd0u9wpExJcOLGEWik3NZirutUQlQbpHnrtE16JuB9/+jsFrJaSP6FarO9/DRb1QvkWUqe6MvCCiNyEziK1qVNQVFNHZgSBwhx4arou4zQTdpMRNAMctwlSbvC5G24vydINJFKM2m8QdKBf6AVMuv8HChlURDpCaG9hVUhf8XllxV/XdfaI/wddPWOCKAOhVzHubeTtj3dlr9BXuXVaY90IWwXt6QRxtWsm/qNu06tdfgiIO8T+34nl0LaKKPn+f0Gc6ojrPxL4BGGQucwTBnCgcDvPgt54875dL6cwJ+lDsv8O7EnRb6VeodNNUSDMJEn2y+gI9DGMuRqlccCmDKk2WS+8g3I9mxt3ylkGdzeH6/7nczpbKz2bpUnqOV1v5guwYLCo9OHzOb1kRVENd8eHQ6F1/Oi0m+ViPpv98eM5DVa55ftLvO/GH4m11tXaZZLv7hZPhV2uF3YWuid5Ju4N95W+2F+2x1Y/3yg3Grr+troMMip4/TWtnndkFG3aE/qYoZ18Z0bafK3qLf12GVbYQrMq2fXf8seglxzWD9Vl4TWptTJNdTxN+ifx2k1GL490mOkVM5kjXQ2Ws/fa/FhloxfSpg8PpdLHpN7az/K5ke7XCoviNqkXaueCvmSPMhvv430u+tU+vTQK5WGxGpFFZtXqbLJP6rHyumXln4v8QN+dLnG2vHqq8c5mcKg04ly71SmtTjPauSOi+VEfbofycqqxl9Wg9vQ636jzrrJgd9VN8Y3NtwdSeJTLki6Kn/2kXWuWguFdJRzEWTrqJr1CdxSsFodauxH3j8tucZp/0HEyHM569cO5nF+ty+yuWV4Py4XKslteCD4vdui5okwHvqCfs+UiPiS+pSHTjERcR1GkpAqnSoTzUEZzLbj5DCYxnSkWSLOikyjiEyIDOpkRReJQs5mM0l9f/wHCxE7b", \n      "device_id": 23, \n      "id": 12, \n      "num_data": 468360, \n      "tid": "gAAAAABcc5_jp9eHuXaD1N2Srcyt51rOpfKlUNye-NTsj9c2K-ZKrpgoKYt59mYdTXrNzQPDwdDtXogFtBXRf_d21RzWNBBZ2Q==", \n      "tid_bi": "c4dedc6cfb2d4fa1d298ccb7a1b3309a93cd241e23b04e33b11deef1e8d1451d"\n    }, \n    {\n      "added": -1068054143, \n      "correctness_hash": "$2b$12$o5DZEBEE2IzNez1d0Qj2Y.iqTzFpeo3CTfcOGkgSXiMw.AYwEf7fW", \n      "data": "eJyVVdly4joQ/RWKVzKFJGvzVM0DWxIyhISwJMPNLcrYZt9tEiCVf79uqeXk8c4DYAmp+3Sf08cfxZAWfxY+irVROl9FsXkejcJVkCSjUbYqjs9pnBSvCtnuW7A6xmb3H0GvCkJfFXT2oURdFVS2QamXPXDYybZF9qCyX5n9q7M/dPYL18xxSpm9LH1YZF9c2btwTZtNOC+zTQZ3IAA8UAlfBLayLy1gxTEMMakZpoCAGu57cIbaQDxbCGb/9CEBscB4dt+HWihg0vYw3M4DK/FtoXEB9UDlUiJgDQUyZneUnwOG0IxgTuawwkEokRJhbwjP3lJflRj0wqaCvgjuatcWupLYThuJY144YqAJRGWaBgwZdmwZrhPEFm3rw/yGBJLF1BgSeqcIVuOogu5CePhwjcF9HzkQTgzS9cYCUEj6F2VQCUA1uCETZNWe6xbBOMACxwwGD7NxoTvAIXwURjC5tJ+nIphKoTiNGKG12kOefILgoBEKWwqpoDkARCk8aVssbGEQDLD72HJDMsrZqN6zLAmBwEz9IAeLTmNgQrFK7iMygOq7v3L9G22hmAz7ZgAFxhSYVeVUwy7PpUtwHCy3FAcoC/zvZzbltf/rABBQaAxj8PmoIBgOSK6cLRCsxJgGd/PuIYMcTxiBWiq0Pc+RcITrJsGSiETnrJh2MhtBoTKEmyCAJakt8GwqpD+Y97elghLy4bWVuZmCzEAv0O4kAfZhEDGnF+dERgQMh84anYdhrQkhdjO70nJmhZP7p6lKIwSTmVs24Q6Uamvd/XWx4IhQrJl0yKccvzqXr7M0IAiQc2cVuUUw5rh06oVzsMMVMghtMrainWW64QIIytm4sbmcS+E0TfGNklsyYDB9Us5lGMFWmmuGROcK0lXgBkX63zps0vFvI+rj20E6cGgH1tctKHRM0LhxC+dl1mEkUsb1t1HM3R41bBvwzTwU4oa8pptukow/IR3GJJVTDs/fNhSHyHcT495Thj5ouCkJXw+Sfslmt13NQxiTYpIefoJ4CvTHTb/R7RUo6CVI08N8fAT1ZILJDxXNfIXMKC1YTV2A2/tKbdS9rTC4u07y/Y/XYqV185otsza9Fu8f6g1YMFg0B/D4WlzGtWC8jJuL+lL75f2uM5jdHSu/fr0W4VRtvpvFh158Su3p5r6cnN/Uno7D/uTuMggmN/ql9KZE+/Deng/1OL2/vPCkK5e8sr4bNkSdv6d9viJpnZ9uypcmG5/LQbwq1c6t6noznTTbsaidD6J7enzTp83eq1OuS+0p7T3rNK3SXb/Rbq+vkzAkhLw8zmK/cdpUkwd2P02eZtFifQzHwb7avZXjBaOVTqkftJfvnldplTv3l872eVO+eeLzWmfW3tx1N+N9aeJtA95bXeT8or1FLB8f1GG1bHV64WzuxxcSyXI5Krcq3UOz97v0nq76D40hva3Whzzi1T/Dyt12uNuud8vG4vgkO42ZeuNqOg1XL5Ok2jp2WJlteJO+XHx523xsJpPq9vfDvd8ZeIM/60VlO6kOTnRzrWu15+dr2dqej/Pr+THUs5K8XPqlyexSClu96p+MgU/gM5pP4yR1lMqIyomUUcRCyZgXEDmmZBKLwAu5FFFEyFgEE06V5wd+pFUw0XEUM0Kz89Qnovj5+R+JE1C+", \n      "device_id": 23, \n      "id": 26, \n      "num_data": -1338610833, \n      "tid": "gAAAAABcem_Lh0-Angt4oGNlL8KiF9a3rDvT_TB3gn6RD_W_ladmyIofV20hQmhlThAZwKeqPAw-XaEFZuDcrmVHhqPx7bNjQQ==", \n      "tid_bi": "8b8877ba600293e3b19d263d27d3ebab1a2ed49b452f5e77622c18dd7adb3279"\n    }\n  ], \n  "success": true\n}\n'

                fake_tuple_info = {
                    "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
                    "integrity": {
                        'device_data': {
                            'added': {'seed': 1, 'lower_bound': 1, 'upper_bound': 2, "type": "OPE"},
                            'num_data': {'seed': 2, 'lower_bound': 1, 'upper_bound': 2, "type": "OPE"},
                            'data': {'seed': 3, 'lower_bound': 1, 'upper_bound': 2, "type": "ABE"},
                            'tid': {'lower_bound': 1, 'upper_bound': 2, "type": "Fernet"}
                        }
                    }
                }
                cmd.fake_tuple_data = json.loads(device_cmd.encrypt_fake_tuple_info(fake_tuple_info))

                result = runner.invoke(cmd.get_device_data, [user_id, str(device_id), device_name, '--token', access_token])
                assert result.exit_code != 1, "Attribute padded incorrectly."
                assert "Data Integrity NOT satisfied." in result.output
                assert "failed correctness hash test!" in result.output
    cmd.fake_tuple_data = None


def test_get_fake_tuple_data(capsys):
    device_id = 23
    user_id = 1
    valid_payload = b'{"device_data": "this is some encrypted data" }'
    mqtt_client = Mock()

    invalid_msg = MQTTMessage(topic=b"x:%a/g:%a" % (device_id, user_id))
    invalid_msg.payload = valid_payload

    cmd._handle_on_message(mqtt_client, None, invalid_msg, device_id, user_id)
    assert cmd.fake_tuple_data is None
    captured = capsys.readouterr()
    assert f"Received invalid topic: {invalid_msg.topic}" in captured.out

    msg = MQTTMessage(topic=b"d:%a/u:%a/" % (device_id, user_id))
    msg.payload = b'{"device_data": {"added": { ... Invalid payload'

    cmd._handle_on_message(mqtt_client, None, msg, device_id, user_id)
    assert cmd.fake_tuple_data is None
    captured = capsys.readouterr()
    assert f"Received invalid payload: {msg.payload.decode()}" in captured.out

    msg.payload = valid_payload

    cmd._handle_on_message(mqtt_client, None, msg, device_id, user_id)
    mqtt_client.disconnect.assert_called_once()
    assert cmd.fake_tuple_data == {'device_data': "this is some encrypted data"}


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_divide_fake_and_real_data(reset_tiny_db, col_keys, aa_public_key):
    device_id = 23
    rows = [{
      "added": 2116580122,
      "correctness_hash": "$2b$12$RzQ1VrzQVTA280pSAG4IyOXsZMplZNi67hp.XpF3ygPtTOW6EbXQG",
      "data": 'eJyVVV1vEzEQ/CvRvTZIXp8/kXioCqKIjwItICAoSi4JBEJbmpSCqv53PLvru/AGD2nv7L31zuzs+LbpqLk/um2Oprv1ZrHk5+m028y22+m0vDXz37vlthmPyurP2eZ6yasfPY1HPo1HufzI2vEotuNRcuXF5LLjZMH78iv/iQx2ylPweEN8CYvlf451oWRKFtk4Fn8Ie6asx3JaRC4O1sDUykbOsoEDkTVlfOVlk0zZSZwsSKhDPZY0vhSaSmguESHU70py4EvloJA0IXn5nHGiJC6lAkbxDnUAgLF1NegDowYQhoQKwJDv0TL+KImHig0paVyupAXVeqyRDKnnpay6JAscDDK8UfYT1RerzBBJGSjOh1pkrYJa7Q2qCH4fllTptDgJstoY7Rkw58qzFWUwGzgdZEevnEIi6CTjkZNDhYhcHAjUrA0gQa1oCXeDJC8yQIopCpHSevQvCju9zLhUEUT6q3AmGhG+AoIG8J0PlUOjwBHCnNjaJwgJAsJ5uppEFoK0rLioX4OZXA/HB24gdJB9hQuYaGkKCgucco+Ju5j1KZF2DT1lilNdpF5MprLeL4FolMjtQjIeA5FZ+HRX5v7oXz2BByDJiOSqE/KqBx4twUYakOOefGR09nmSfol18GbY9wSZMCuVo0VRtS9IWu09ybwJYUHZYPZJBzOQwPzNOOmebf8bsFcsSfSs8+rEE5hi9ss6AElVG6pzJFEwVA0hDbLSUbeqz2j/4gLDKq5FOkSklWAOkM1pdsapWAXs5X+jhXtUyxfD8VouW0Q/KF6OZIdrVYLifanXIenoJnVaM7gVntEtVz0t9VIABbJcG6ny8pJKzbQ6k2pFC3O151FdR0csqvtn9XRT7yucFOtO0CJp8EqnKtYaorSAPdbEmqPVe6ZeKYOb71u23Ipu37Kz1jbcZr3985AkFX1b7YP0VsxiFVCByMUNPhT0roBoYtg7N9W7T8K9TpKX9gUalHN5sVl3GJVmu7u6D/2M6N7jN49Oz0YEycx2u6v1/BoCKprpgxqesc6y2GabzzXB8fPDo+np8aHFt9+3/frtpDl89nhSXgvYSfP85OEjvFi8PHmLx0lz/eH96nh78ePqxasv3frru4NX7dmHwwcPJg2ijtaXX5ZXZ8tfO4m++HZ+82N3ffCa8vnLdydPV9ldHNwg+g5nL9afl9tdPX7ZkSu/5Bed6Wg2m3vrZq7IeL6Ydba1cb5qKS1WNs+NczGtOuNbb7MhR9bH1Nzd/QEO2OWF',  # b"test1"
      "device_id": 23,
      "id": 6,
      "num_data": 464064,
      "tid": "gAAAAABcc6oom25HAPNEXj0boVX9KaUIuqL4V8NVAGVO66AdnZ02aGVz_cjuRh-XuoK2BCIn9b6R18MnjdNrtja7mzUgXOlHzw==",
      "tid_bi": "19b0ac102511621a04272dc74ded56124ec487e4068e32f5274cbf04e7edbd1e"
    },
    {
      "added": 2244032082,
      "correctness_hash": '$2b$12$IG7lSJbUlJ2xxPlWvHwWN.gowMe/Xqg/lxmueyqlaBI4TCHE.BxU2',  # Fake
      "data": 'eJyVVcluE0EQ/ZXRnI3Ue3UjcbASSCIIW8IiYWR5xgsWJpsdRBTl3+naxuFGDh5P91RXvVf1qvq+7W37vLlvD6a79Wa+oPfptN/MttvptK7a7m632Lajpu7+nm1uF7T7LdpRE/OoscbVh8OHLfKWY/35UQMed6G+AG9Yiw9Tj0EYNcWMmpSG3YiPuoT6kuovFDmNoXAR6rksa2vq4YzWiKNupvoxVD8ly0f0jtbk01p6YAhrOIRgJvRoagWisRwpAAeIiR0DosaA4pscpcKGhD474ZKAicVKMkYNjPHwCyLGf/qC2ctENDDJ6Dls0iO4CY5DRccGkixEmDnNlEfj+TMQWav0kDuBdJo4wo7OiC0ZAH0rAika5UTYsrwYL2QwAVhUXhTODsEtUiAwEj7LAgPkJEw5VXFgUlg0mDDQSqFEQCXF0IiTCQKZkhiUEpfTSDmJK6UKVZlAqKJ51sqIahAcKdaIetiT5V0iX0QPBAeRMHdgJ6DKRuhoSjQRBRVUE5tFLywez6kiMI79YKYINyc97SESQ3aU+DOeQTRooeiYPaoiJjFFIXO8Iv5t0J50km9JC3qh1oPvD7XZD/53EBBH7cwgvYUtThPCaHmo6d1QLKsNlB9VB0ArYLVHjQomD46C7DNJTRUMfUayVSNMQCraNYGTgL2VLNO8I572mfNPJYyJoxLoJHIMk5JgOApojyEO7jov/ZEeq5vKI01OFSROZT++rBTM8Wm05URbLaeXMRV0JpPwCzNlqldP5orcqLg6OakY1PDSzjjFQNA/ugZQ38zZDYNHckVweSCzDDxP3qwjKugU4gknswHpg/nnqwyJrFNJMufl/tC5TNqjIzilCLCO4SLaB5FL0SlDnVCUQxzt7xSCXwbZRtXmP6DBaLvJXQc6eLwOXlBlw/6uotmHKqWwNM6FCJY2l0cCIdUVUZxRa8dC4IvM6x3qtT0ydw3NJyO3L9+RQdOk2aM+sXv1XF1u1j02S7vd3TxHDTX22dGnl2fnjUXZzHa7m3V3iyKquhmMWuqy3pHgZpuVOjg+HR9Mz47HDs/+2g7795N2/OZoUpcV3qQ9fXf4EhcOFyef8XXSro7s3avj24u78c/Di93Ha/v26Or1+MWLSYtWB+urH4ub88WfHVtfrt5/fPdhdW3+HJ+cfF2MTTo/+7JC6weMPV+vFtudhl86n8D6tFzOZl2fXD/zsQuznLsMKXS5X7gux+DnDkwXknXzZd8tS4GYYz+3oX14+Av3EuQO',  # b"test2"
      "device_id": 23,
      "id": 8,
      "num_data": 466263,
      "tid": "gAAAAABcUvNYvD4xkZ7pHxIBtpEWka8UVdCxmvR-O886BC06ILrqWqtT59ZKVgz7k8-TtIstlYzubq1ZZp_prquskFw5ZWNVSQ==",
      "tid_bi": "8b8877ba600293e3b19d263d27d3ebab1a2ed49b452f5e77622c18dd7adb3279"
    },
    {
      "added": 2328638717,
      "correctness_hash": '$2b$12$eWHqbmbvv.Egj/4Jy3.msOdnZ0vz.iaMRdgHJ5d9/Ymmczjr7wbcK',  # Fake
      "data": 'eJyVVdtu00AQ/RXLrwSxu95rJR6qFiiIi0oLCBEUuY5bgoIoTbhW/Xf2zMXJIzxk7V3Pzpwzc2Zy2w62PWhu26PFdrVejvS+WAzrfrNZLOquvfi9HTftrKmnP/r195FOPwQ7a0KeNdbEWVNKfbFm1qR6Ehw23ayJCZ+xM4FtUrX1HT4HLJkv0E0xxOKsLMHPmgzXBgauLiFihyAde0vkiCJWQwJVT3Nkz4gZEp/n+oxlPwZZGQYcCKsX7/RGrhkLwttq4YG48E1rYZOYEALBea5nAXmw/GRvwIdkJPCp1tlyYHriVlB61aAYNgJ+ugDc4EK44MUxZKYuQa21/IU28JUd3y2Jk0j+NDeaxmQ0fcgKEMM0eM0Q7tbDSPZFABBzSnWQjXVaZThMncCAcRZK1nSa5Y7JwLTQgdUFSIAzW4mHwLD1SQADEZFPkjYzeWAMUao3UQ+T3KaaJLHOSgb5AJksGqX8kITzHg0WrGHuIIkrRMkmCR2DAMcxdQXioIzk3kopC5d4X6rcPoXzTYToVHXKvuxeBFFlYJc5c040WVTpwkKMedcNSZUQJqlnKZD1H+9qlx/96wTwhScAECFsEHRTHyTVl5ECUkYjgw1xv4E13ywbyzUuOhayNLwvO/nCEr5A0E9VsswaH0LcwYmWqf0mbva+6/6XJImbGKY9YNR+pFpExjGgUQdHhkstKRKgZNBAgVRIwarmKBYdk6WyQiEib9UY0kyzBz2UVP5BkRDdSpW5Xv83WXRHEI2jYNT2JGAj7AwHofkkrKnMamxE9qzdXYaS0umke4oMNKuzfrIpKsocJ+oyP/30eRpQQZxSxmjcR9GDkyHLwtDm1srxP4HyQ8/lNLmKnFPuxLib0fglvz8aqE5ReYCr10Y0rNEctaRGnHgdmhSeh69ntVD35j0lZWkHSCjKtKBEIzBGik+ayKxfCusoyXCip5PGkd6g4upAsjvRXH9drwY0SbvZ3hxAOo29/+TNo7PzxkIt/XZ7s7r4Du1UuUxGLXXX4Ehn/fpKHZy8ODxanJ0cOtz9spnOb+ft4fMn87qtPOfti1fHj7Bx2Dx9i9d5e/zg3stvN4+7Yp+7Z69Ozn8eh8+nVw8fzltYHa2uP4035+OvLVu/u375+NwuD7+6B8PTP69D+PPsy/tTWN8h9nJ1NW62Gj4NxY3eX8TSFT+YIRRTljkt+1hGt0x96S4vbR9i8g7LGHtjBuvG3pVhSJe+vbv7C/GT3oI=',  # b"test3"
      "device_id": 23,
      "id": 4,
      "num_data": 471232,
      "tid": "gAAAAABcUvNYhiqIYBpG848jbgdwY92eW2HUGSwjAP4NL9rAcSCTmeU2noYgDnlpy7XzLDu4Ly4UaGMjBqUeNlpryV_BEYbcug==",
      "tid_bi": "db58b3a148680f7575a07532a555403a9b85a4c43268e0e0b0c911a145f3d59e"
    }]

    integrity_info = {'device_data': {
        'added': {'seed': 1, 'lower_bound': 1, 'upper_bound': 4, "type": "OPE"},
        'num_data': {'seed': 2, 'lower_bound': 1, 'upper_bound': 4, "type": "OPE"},
        'tid': {'lower_bound': 1, 'upper_bound': 4, "type": "Fernet"},
        'data': {'seed': 4, 'lower_bound': 1, 'upper_bound': 4, "type": "ABE"}
    }}

    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    insert_into_tinydb(cmd.path, 'aa_keys', {"public_key": aa_public_key})

    fake, real = cmd._divide_fake_and_real_data(rows, device_id, integrity_info)
    assert len(fake) == 2
    assert len(real) == 1
    assert real[0]["tid"] == '-1'
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
            "device_data:data": {
                "private_key": "stuff",
                "public_key": "also_stuff",
                "attr_list": [
                    "1",
                    "1-23",
                    "1-GUEST"
                ]
            },
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
                'seed': 1,
                'lower_bound': 1,
                'upper_bound': 1,
                "type": "OPE"},
            'data': {
                'seed': 2,
                'lower_bound': 1,
                'upper_bound': 1,
                "type": "ABE"}}}

    assert cmd.get_col_encryption_type(col_name, integrity_info) == integrity_info["device_data"]["added"]["type"]

    col_name = "device_data:data"
    assert not cmd.get_col_encryption_type(col_name, integrity_info) == integrity_info["device_data"]["added"]["type"]


def test_decrypt_row():
    row = {
      "added": 2116580122,
      "data": 'eJyVVdtu1EgQ/RXLz4PU3e4rEg8hsASJLCwkQYJBo/HEDrM7bKLMBBZF+fftUxc7j/BgT3e7q+qcqlM19+3Gtk+b+/Z4ddjuLgdar1ab3Xq/X63qru1/HoZ9u2jq6ff17m6g08/BLpqQF03u6uPrExeNta4u0qIp9QmmPvU3WXyor4SP1cJ3/MHXdajrVBZNrNahPjnUy87ypQS3Vg5NtUZMxInVOtbD7PDBw6SuUkIgvEwNXQpHtCaLtTWW0SBwgk8rEK0FeAPgBjvPscmA0BTy0QkRMAMmAKfPIepl2/GnmAVZiswBkEGeHVDwIFFw4hMjRiD2BiAm8hVmBvRIeL3mEdlK/miBoLypr1jEizNKm/gXdsWUPedv8oCaZaNGOEnqj9AQeiDyEgGVByBKAQ6KPASV0gkbJttJlmN8rIYgmuFIQXIndUAuiKgJ7F+qGLj4yL5Pk2+jUuA6eMaWonxLCulRdgPDYYES6TJLlipoJ/2qupGuICVEAFK5U99GQKoEstXDJPCwI4IqEFCIomnEJqF4Dpu9wKT4pHakDskhcqontBzncsIK1SdJM2qSxT3w56RqFzllFXIN9uWhdvrxr04B1CeoVICUckFoy1wmPpRyInM+ywEVL4h2SVBuzq1Qdyw51nwSLTutV1EFTo3spSxIE4zgKoqEomV+P4mgfeK632XKXe1kxjkWVJgmhoKY5oMtwoEFZeaKE5kYNBNoLfQL9YwVI2oKIpu1AYo6RBmjjDIyoElnvQQlypUu8735bcKk7KxTq6hrTEGMCcxhFrHhg6hTmsrYce951T03YZBRDeOsvRtn9RVOGg0zHev8Ip10E7/MNYBDqoPVLPk5idkqOqlOcPo3VQQVAuEkJB3ZZZ6KcEr/MiLNqKimSSwDMGte0jSRZYQRYZRFBZK19jQLknKWARq01cM08NMj11mVVuSw6D8esM+T1aoYdSQkw57K5M1ooMC5Ip5AYWfR3Fzvths0Srs/3D6FdBr75NX5yw9njYVa1ofD7ba/g3aqXKZLLXXYxpHO1rsrdXByenS8+nBy5GD7bT+d3y/bozevlnVbQS3b07cvXmLjsHl9geWy/fP60934/fzk3/H9P28v7s7+OBpO7Y9nz5Ytbh1vb74Ot2fDfwe+Pb74ev2Xeff+ef8u9R/PXr/5+5sZr3D7AbEvt1fD/jDxKpdj2sTN4HrbD13crLtxTHVngvO9G5O3yfT9sAkhjf0Ya8F63w+ui3EIphvah4f/AYEK4uQ=',  # b"test1"
      "num_data": 464064,
      "tid": "gAAAAABcc65MJ0PJrx3iI-xwnUFJkHOEa8JbQWQ3pPh8dLooKLFH9sJuLYeDbHIlNxWbDr512mKnBBFBc2WxoceFgM1MTW_0SA==",
    }

    keys = {
        "added": ["8dabfaf75c380f03e95f55760af02dc84026654cf2019d6da44cc69f600ba8f7", "OPE"],
        "num_data": ["3130d649f90006ef90f5c28fd486a6e748ffc35bad4981799708a411f7acaa60", "OPE"],
        "tid": ["9692e6525c19e6fa37978626606534015cd120816a28b501bebec142d86002b2", "Fernet"],
        "data": [
            "eJyVVstuGzEM/BXDZx9E7erVXykCwy1S55BDgbQFiiD/Xg05Izs9JQd711yJOzMcUn49Xo9fDq/H8/n78+Xl5Xyev47f/v56fDmeDjP65/L8+9GjX/dxOpR+OtR2OvT5afNTbF7LvKbTYZ/PCmJbxM3q/Mrzrs4VtTLS9ti+NwTm2jrzIrcZojPQ8+1qKccWX55TLG0z2DufWvK7wk0WGas9vE0G1/xReqAAek5NYC3xV98i/XDUO1kCRgIugEx88QTSwXHEIksjtkEvPLCEfDVWW5qRNmI78oFaaNVC0tpJvIkrKHZfogTAvvQoheCRBvCAHagg4RiE67BWDRCG3AAMASwZl3gBfR0U7qj1rrKAekpkloVlC+6wySBlXyAenghkysQ3SAyJoTOSo9zAC1m6k0lClBcsvNcXbUF0F9YiIK6z1yq2RRYt8zLhassrT5/thC6X+8sD1ha1aV3uLkEIYnnRIL5Xooc2UQOsMvWNMSKMnlAidVbAcijmbWfLDa5X5/ve98KPz/KDtk6i0Br4IHE0Y6a8Ts/CRHCiW7epe7xSfWmzCWQ4bFM70RNNnig3dfDbTWmN5EJrKP8fxcfz9Xq+PP98uny47S24EtTO8SOzRvdl6uBfoNpX52ksFU6ywobzIGq880FtmldOAwzQnAh7/xvvdw0Gi+zeQ6vbXdpOf2EYVM6O5SskKFVj0TRO0Az7RmMVmpJFyGsmpADlBsscw9FMeHFlcSLh0DgSp6bpnjXo1sS73+Tnx1B/IoNDvvVpDedpKuIaji/qNGG9ez/VHhpe+80renFXS5Glr2tqNk9RqsSud10J6BhhMINvjKdZFJvUHHcah2EyzV/UIxwb3jM55IxDhnX3ocdzrDRN4xIP8fKm6b+C9R5CpnBCUHk6u6LqNnppnRr1dqy6hSh0YSG9G8DZzzOMJ9wMuY7e4fFQdcI0TVllzWwXNL0OQz+svDh9je32bpglzW7/b1FvR0eTSuuvwhb6xim4Pby9/QMmWbTA",
            "ABE",
            "eJydVstuFDEQ/JXVnhfJ9vjJOYgPCJxQtAooF5QDYgMSivLvuLqrvCPBJTmsdsZj96OqutvPx5vj+8Pz8Xz+9nh/uZzP8+349c/Tw+V4OszV3/ePvx5s9UsJp0Ppp0Mf8z+fDjFu86GdDi3xpc+vdS7EsGEFyyHiaeBpfixzvc2XPJ+bfYGd0Hyl1rkjYGGe7GX+zNbcX+fXAffJz8eIrfM3+KFrw1xr8z/jZIw8XqatjPiCHCBqeB2MsyiOVpWChVd8HyKzYCzeGJhi0/HRHJaYoscUQ/aTcGkHEFFH+NkjJDzJoyv2Ai+Vq+47+meYRGqGdmdqWLCMMilIK5HhPiqP9E3ZiQ1L0fgrZGM4iPSNLSBg7q/2u3uZcrj5blqJr1VMRTybRxxDYMrSiAUV4G3GPgZTt+gMkqUzfC9C2uDZnBZgunhdAsydhK0Hwx0UOUqVfmEG2bbiOJRIMdE84IMCQV8n2/hWK5kYxie8pCC5wx/yNuwlVxMM/JbCo50/hyaK2uwRGbWFBioNIAsLq7r11pbPss84dEUF/TVKHmbtk+8pV1U6rJunY4rL/ltlyHLNXiaOOIvOxAfb9rtKJr5L22vlYh5WNcBVX+XZnB7g11j/5tqL0kQhwcWFqIBjFRkEDtjwvbbP5R9dD62KuixOomxWdbO4E6/JGYF39bXBIIxABI9gu6Rt/aBwAeD6w8YY1MgGmUKBGyfqJ4VoeG2Pa97WQZCyGYTazRUF4wvbrhYsCAPj2rkbmTVI8DYkXFN4G1JwUOJFEt4cF1d5cl8OcaJDa+bde9d/FfPx84fbT68VjSkje/mDgqGZw46W3SGwKOrYmfkM5eu8sVoAmdGwCdRFscx2lkJT1+6JlqwoAyvLdFnlxHtv3Qs4OgWNrHXNHutKSfiyVXhlRNVJZDtZFHlb6uxTwQFnkWQlauwmV40V/8YQOMYNTg4mH/ZSQRKKxUUIiPC+umJzyS/5FSJmLbSyrSZPIavmOgXBDkpbQ2T2f+eRD6Qfr5tIGPjeYoKQ7X4NKORgsC7XNUOdsBPRuu4B3mCTG2q6bKwJ1tRhvFS6FBT77uJhvaZrIrEvZFUiCucNjVRZds1ydZK6bhdpP3ivQ7+zReWuScEiRZyZlqy+U1Sh6/ZXpY6qfNJuslSNx6HKKJSx1/9bal95Nt1mkFFnKD5rKUYTJGt5sHuuorIi15wDOyZ6dgDrkzYVpMUmavO+0+TrFc+EsS4pTmS5ivYWoR8vTz/fR2RkDyB3PTsGdy9/AbtMQWU="

        ]
    }

    expected = {
        "added": 985737600,
        "num_data": 1000,
        "data": "test1",
        "tid": "-1"
    }

    result = cmd.decrypt_row(row, keys)
    assert expected == result


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_save_data(runner, reset_tiny_db, device_col_keys, integrity_data):
    user_id = "not a number"
    data = "data"
    num_data = 1111
    result = runner.invoke(device_cmd.save_data, [user_id, data, num_data])
    assert result.output == ""

    user_id = 1
    tid = -5
    device_col_keys['tid'] = tid
    device_col_keys["integrity"] = integrity_data
    insert_into_tinydb(device_cmd.path, 'users', device_col_keys)
    result = runner.invoke(device_cmd.save_data, ['55', data, str(num_data)])
    assert f'No user with ID 55' in result.output

    result = runner.invoke(device_cmd.save_data, [str(user_id), data, str(num_data)])
    doc = search_tinydb_doc(device_cmd.path, 'users', Query().id == int(user_id))
    assert all(s in result.output for s in ("added", "num_data", "data", "tid", "correctness_hash", "tid_bi"))
    assert doc["tid"] == tid - 1


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_create_row(device_col_keys, col_keys, integrity_data, reset_tiny_db):
    user_id = 1
    tid = -5
    device_col_keys['tid'] = tid
    device_col_keys["integrity"] = integrity_data
    insert_into_tinydb(device_cmd.path, 'users', device_col_keys)

    key_type_pairs = {
        "added": [device_col_keys["device_data:added"], "OPE"],
        "num_data": [device_col_keys["device_data:num_data"], "OPE"],
        "tid": [device_col_keys["device_data:tid"], "Fernet"],
        "data": [device_col_keys["device_data:data"]["public_key"],
                 "ABE",
                 "1-23 1-GUEST 1"]
    }
    with mock.patch('client.device.commands.get_key_type_pair', return_value=key_type_pairs):
        result = device_cmd.create_row("data", 1111, tid, 2222, user_id)

        assert len(result) == 6
        enc_tid = result["tid"]
        enc_added = result["added"]
        enc_data = result["data"]
        assert decrypt_using_fernet_hex(device_col_keys["device_data:tid"], enc_tid).decode() == str(tid)
        assert decrypt_using_ope_hex(device_col_keys["device_data:added"], enc_added) == 2222
        assert decrypt_using_abe_serialized_key(
            enc_data,
            device_col_keys["device_data:data"]["public_key"],
            col_keys["device_data:data"]["private_key"],
        ) == "data"


def test_is_fake():
    real_row = {
        "added": -959,
        "data": 1000,
        "num_data": -980,
        "tid": -11234,
    }
    fake_row = {
        "added": -959,
        "data": 1000,
        "num_data": -980,
        "tid": 1234,
    }
    assert not cmd.is_fake(real_row)
    assert cmd.is_fake(fake_row)


def test_generate_fake_tuples_in_range():
    fake_tuple_info = {
        "added": {'seed': 1, "lower_bound": 2, "upper_bound": 5, "type": "OPE"},
        "num_data": {'seed': 2, "lower_bound": 2, "upper_bound": 5, "type": "OPE"},
        "data": {'seed': 3, "lower_bound": 2, "upper_bound": 5, "type": "ABE"},
        "tid": {"lower_bound": 2, "upper_bound": 5, "type": "Fernet"},
    }
    fake_tuples = cmd.generate_fake_tuples_in_range(fake_tuple_info)

    assert len(fake_tuples) == 4
    assert "added" in fake_tuples[0] and "num_data" in fake_tuples[0] and "data" in fake_tuples[0] and "tid" in fake_tuples[0]
    assert fake_tuples[0] == {'added': -497233321, 'num_data': -623552190, 'data': pad_payload_attr("-303927213"), "tid": "2"}


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_parse_msg(runner, reset_tiny_db):
    data = """{"ciphertext": "gAAAAABcOiilUJ_u1tRSQ-iIghG4DgPOfCjUXOL2_FZ0f2XcPHcp5rDMu1dQMvFZ_4VlPr-QjG79HNes-F6bDxcr7K03R0r-8bWEZaFcS3j-ri0C-sy33Fc=", "user_id": 1}"""

    insert_into_tinydb(device_cmd.path, 'users', {"id": 1, "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc"})
    result = runner.invoke(device_cmd.parse_msg, [data])
    assert "{\"action\": true}" in result.output


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_save_column_keys(runner, reset_tiny_db, col_keys):
    fernet_key = hex_to_fernet(col_keys["shared_key"])
    plaintext_abe_data = fernet_key.encrypt(json.dumps({"public_key": "stuff", "attr_list": "1 1-23"}).encode()).decode()

    data = f'{{"device_data:data": "{plaintext_abe_data}", "device_data:num_data": "gAAAAABcRHibuWXtMvF7XgSN7FR-cHyNl2eDb_HHPCuTjqtdMN2VxxZnSxGCjkoJxRNIGMcpBW-z4n1wynPoCCb1VanmH3EukMPwpf7Vwk9WytkNR9h51ApyGt1QEkaj_JF2A5jKu-vw", "action:name": "gAAAAABcRHibSiR3cHtaSUSk1ipKP_7csl3xTCd4J-JesU8GPlC2iwfblksE3kvuV3U2mAYqiYe3UuYw04JPbYDYaFePY-YTUAzie3OCRzwuMTE6tE9UBJtJ8wUNJSctZnrvSi0rcPzQ", "device_type:description": "gAAAAABcRHibvjQEIYiaSi9yXLm2VPbgPsmye1mKv9DYF9ktCixOf6Cq03dKc1-ZpxucfrKJXOyT7vyq17cfxyrN9k-Bj4pi3BV7M68fLTR__03lK32W8LOLkMLWdMvxcURU1W8gg91f", "device:name": "gAAAAABcRHib0mxfmRE3mg4ALX3XPjP7ZuVQ69NiRdebiNCE-40wZuzzNV1krKcnZeRZVWXwYf4xjYLNNygY-kbbgxltBWNJ5rLanpBIqTeoq8uI9up1bZ_vFFCiGPIjHTpYkMnF5XIN", "device:status": "gAAAAABcRHiboBSiAuKLxvSqS1yu4vOR8FlqGBOnzJSQ85e5UShmQ9avtLAXx_w9fKad2xILHWbi_uFywJML8ukoDGB7iiHkLT39iOnrUCAQHFyOdFERixgl-iFHMji-S1YfGKGwxRIU", "device_data:added": "gAAAAABcRHibuWXtMvF7XgSN7FR-cHyNl2eDb_HHPCuTjqtdMN2VxxZnSxGCjkoJxRNIGMcpBW-z4n1wynPoCCb1VanmH3EukMPwpf7Vwk9WytkNR9h51ApyGt1QEkaj_JF2A5jKu-vw", "scene:name": "gAAAAABcRHibVgsVHRls8IGj95TdFKraKbGfyf_TvDzjg0KV_vu-HawiISBzRaxwrFV_QHI5jA73CTM2dF4ePENaMe0QtIJljtqCBUSRhoQideCy0JL4hDAIJUzpGXFK5RMC2fJHUJ17", "scene:description": "gAAAAABcRHib1iH0Bs9sHff-dt7FY9XOUDzARN-mwaq7eI7iLYYwtmBcMkB3T5ChNnoNWhIRLnh_lQLmvCT_itBvjoIHydBVdIcTjzsyHcTMBUdlxPmohokOjunxdMSCY0B48-pYqzsn", "user_id": 1}}'

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

    assert doc["device_data:data"]["attr_list"] == "1 1-23"


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_register_to_broker(change_to_dev_db, runner, access_token_three, reset_tiny_db):
    password = "some_bad_pass"
    app, ctx = change_to_dev_db
    with app.app_context():
        creds = db.session.query(User).filter(User.access_token == access_token_three).first().mqtt_creds

    runner.invoke(cmd.register_to_broker, [password, '--token', access_token_three])
    table = get_tinydb_table(cmd.path, 'credentials')
    doc = table.search(where('broker_id').exists() & where('broker_password').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1
    assert doc[0]["broker_password"] == password

    with app.app_context():
        creds_new = db.session.query(User).filter(User.access_token == access_token_three).first().mqtt_creds
        assert creds is None
        assert len(creds_new.acls) == 2
        to_delete = db.session.query(MQTTUser).filter(MQTTUser.username == creds_new.username).first()
        db.session.delete(to_delete)
        db.session.commit()


def test_create_device_type(runner, access_token):
    result = runner.invoke(cmd.create_device_type, ["description", '--token', access_token])
    assert "\"success\": true," in result.output
    assert "\"type_id\": " in result.output


def test_create_device(runner, access_token, change_to_dev_db):
    result = runner.invoke(cmd.create_device_type, ["description-again", '--token', access_token])
    type_id = re.search('type_id": "(.+)"', result.output, re.IGNORECASE).group(1)
    device_name = "CLITest"
    result = runner.invoke(cmd.create_device, [type_id, device_name, "test_pass", '--token', access_token])
    assert "'success': True" in result.output
    assert "'id': " in result.output

    device_id = re.search("id': (\d+)", result.output, re.IGNORECASE).group(1)
    doc = search_tinydb_doc(cmd.path, 'device_keys', Query().device_id == device_id)

    assert all(k in doc for k in ("device:name", "device:status", "bi_key"))

    app, ctx = change_to_dev_db
    with app.app_context():
        dv = db.session.query(Device).filter(Device.name_bi == blind_index(hex_to_key(doc["bi_key"]), device_name)).first()
        dt = db.session.query(DeviceType).filter(DeviceType.type_id == type_id).first()

        assert dv is not None
        assert device_name == decrypt_using_fernet_hex(doc["device:name"], dv.name.decode()).decode()

        db.session.delete(dv)  # Clean up
        db.session.delete(dt)
        db.session.commit()


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_create_scene(runner, access_token, reset_tiny_db):
    result = runner.invoke(cmd.create_scene, ["scene_name", "scene_desc", '--token', access_token])
    assert "Blind index key for scene name is missing" in result.output

    runner.invoke(cmd.init_global_keys)
    result = runner.invoke(cmd.create_scene, ["scene_name", "scene_desc", '--token', access_token])
    assert "\"success\": true" in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_init_global_keys(runner, reset_tiny_db):
    runner.invoke(cmd.init_global_keys)
    table = get_tinydb_table(cmd.path, 'global')
    doc = table.search(where('bi_key').exists())
    assert "bi_key" in doc[0]

    runner.invoke(cmd.init_global_keys)  # Insert again
    doc = table.search(where('bi_key').exists())
    assert "bi_key" in doc[0]


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_add_scene_action(runner, access_token_two, change_to_dev_db, reset_tiny_db, bi_key):
    scene_name = "Home"
    action_name = "Stat"
    device_id = "45"
    device_bi_key = "fe65ae5d8665d9b68d8e20dec8fca3da23a881e5df60a132a92882a8c666149a"
    result = runner.invoke(cmd.add_scene_action, [scene_name, action_name, device_id, '--token', access_token_two])
    assert "Blind index key for scene name is missing" in result.output

    insert_into_tinydb(cmd.path, 'device_keys', {
        "device_id": device_id,
        "bi_key": device_bi_key
    })
    insert_into_tinydb(cmd.path, 'global', {"bi_key": bi_key})

    scene_name_bi = blind_index(hex_to_key(bi_key), scene_name)
    action_name_bi = blind_index(hex_to_key(device_bi_key), action_name)
    result = runner.invoke(cmd.add_scene_action, [scene_name, action_name, device_id, '--token', access_token_two])
    assert "\"success\": true" in result.output

    app, ctx = change_to_dev_db
    with app.app_context():
        sc = Scene.get_by_name_bi(scene_name_bi)
        ac = Action.get_by_name_bi(action_name_bi)

        assert ac in sc.actions

        sc.actions.remove(ac)  # Clean up
        db.session.commit()


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_init_scene_keys(reset_tiny_db):
    cmd.init_scene_keys()
    table = get_tinydb_table(cmd.path, 'scene_keys')
    records = table.all()
    assert len(table) == 1
    assert "name" in records[0]
    assert "description" in records[0]

    cmd.init_scene_keys()
    table = get_tinydb_table(cmd.path, 'scene_keys')
    assert len(table) == 1
    table = get_tinydb_table(cmd.path, 'global')
    assert len(table) == 0


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_is_global_bi_key_missing(runner, reset_tiny_db, capsys):
    assert cmd.is_global_bi_key_missing(cmd.create_scene, "My message")
    captured = capsys.readouterr()
    assert f"My message, please use" in captured.out

    runner.invoke(cmd.init_global_keys)
    assert not cmd.is_global_bi_key_missing(cmd.create_scene, "My message")


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_get_global_bi_key(reset_tiny_db, bi_key):
    insert_into_tinydb(cmd.path, 'global', {"bi_key": bi_key})
    bi_key = cmd.get_global_bi_key()
    assert bi_key is not None
    assert isinstance(bi_key, bytes)


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_get_device_bi_key(reset_tiny_db, col_keys):
    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    assert cmd.get_device_bi_key(23) == hex_to_key(col_keys["bi_key"])


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_set_action(runner, access_token, reset_tiny_db, change_to_dev_db, col_keys, bi_key):
    device_id = 23
    name = "test"
    result = runner.invoke(cmd.set_action, [str(device_id), name, '--token', access_token])
    assert f"Keys for device {device_id} not present, please use:" in result.output

    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    insert_into_tinydb(cmd.path, 'global', {"bi_key": bi_key})

    result = runner.invoke(cmd.set_action, [str(device_id), name, '--token', access_token])
    assert "\"success\": true" in result.output

    app, ctx = change_to_dev_db
    with app.app_context():
        ac = db.session.query(Action).filter(Action.name_bi == blind_index(hex_to_key(col_keys["bi_key"]), name)).first()
        decrypted_name = decrypt_using_fernet_hex(col_keys["action:name"], ac.name.decode())
        assert decrypted_name.decode() == name

        db.session.delete(ac)  # Clean up
        db.session.commit()


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_trigger_action(runner, access_token, col_keys, bi_key, reset_tiny_db):
    device_id = 23
    name = "On"
    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    insert_into_tinydb(cmd.path, 'global', {"bi_key": bi_key})
    result = runner.invoke(cmd.trigger_action, [str(device_id), name, '--token', access_token])
    assert "\"success\": true" in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_trigger_scene(runner, access_token_two, col_keys, bi_key, reset_tiny_db):
    name = "Home"
    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    insert_into_tinydb(cmd.path, 'global', {"bi_key": bi_key})
    result = runner.invoke(cmd.trigger_scene, [name, '--token', access_token_two])
    assert "\"success\": true" in result.output


def test_authorize_user(runner, access_token_two):
    device_id = "45"
    auth_user_id = "1"
    result = runner.invoke(cmd.authorize_user, [device_id, auth_user_id, '--token', access_token_two])
    assert "\"success\": true" in result.output


def test_revoke_user(runner, access_token_two):  # NOTE: this is dependant on previous test
    device_id = "45"
    revoke_user_id = "1"
    result = runner.invoke(cmd.revoke_user, [device_id, revoke_user_id, '--token', access_token_two])
    assert "\"success\": true" in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_get_device(runner, client, access_token, reset_tiny_db, col_keys, bi_key):
    device_name = "my_raspberry"
    device_id = "23"
    device_name_bi = blind_index(hex_to_key(col_keys["bi_key"]), device_name)

    insert_into_tinydb(cmd.path, 'global', {"bi_key": bi_key})
    insert_into_tinydb(cmd.path, 'device_keys', col_keys)

    result = runner.invoke(cmd.get_devices, [device_name, device_id, '--token', access_token])
    assert device_name_bi in result.output
    assert "failed correctness hash test!" not in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_get_device_data_by_num_range(runner, client, access_token, reset_tiny_db, col_keys, aa_public_key):
    device_id = "23"
    message_fail = "Data Integrity NOT satisfied."
    message_success = "Data Integrity satisfied."
    fake_tuple_info = {
        'shared_key': 'aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc',
        'integrity': {
            'device_data': {
                'added': {'seed': 1, 'lower_bound': 1, 'upper_bound': 1, "type": "OPE"},
                'num_data': {'seed': 2, 'lower_bound': 1, 'upper_bound': 1, "type": "OPE"},
                'data': {'seed': 3, 'lower_bound': 1, 'upper_bound': 1, "type": "ABE"},
                'tid': {'lower_bound': 1, 'upper_bound': 1, "type": "Fernet"}
            }
        }
    }
    cmd.fake_tuple_data = json.loads(device_cmd.encrypt_fake_tuple_info(fake_tuple_info))

    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    insert_into_tinydb(cmd.path, 'aa_keys', {"public_key": aa_public_key})

    with mock.patch('client.user.commands._get_fake_tuple_data') as _get_fake_tuple_data:
        result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, '--token', access_token])
        assert "failed correctness hash test!" not in result.output
        assert message_fail in result.output
        assert "Attribute padded incorrectly." not in result.output

        json_output = json_string_with_bytes_to_dict(result.output.split(message_fail)[1])
        assert len(json_output["device_data"]) == 4

        result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, "--lower", 467297, '--token', access_token])
        assert "failed correctness hash test!" not in result.output
        assert message_fail in result.output
        json_output = json_string_with_bytes_to_dict(result.output.split(message_fail)[1])
        assert len(json_output["device_data"]) == 2

        result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, "--lower", 467297, "--upper", 469439, '--token', access_token])
        assert "failed correctness hash test!" not in result.output
        assert message_success in result.output
        json_output = json_string_with_bytes_to_dict(result.output.split(message_success)[1])
        assert len(json_output["device_data"]) == 1

        result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, "--upper", 467717, '--token', access_token])
        assert "failed correctness hash test!" not in result.output
        assert message_success in result.output
        json_output = json_string_with_bytes_to_dict(result.output.split(message_success)[1])
        assert len(json_output["device_data"]) == 2

        r = Mock()
        # NOTE: following data is in old format (without padding therefore it, prints (and raises) "Attribute padded incorrectly."
        r.content = b'{\n  "device_data": [\n    {\n      "added": 2116580122, \n      "correctness_hash": "$2b$12$GxqMX2MKiEtrOF9YVL2TO.S7vf7Jc4RP8MXgL9d0kgIJfthUQjxM6", \n      "data": "eJyVVV1vEzEQ/CvRvTZIXp8/kXioCqKIjwItICAoSi4JBEJbmpSCqv53PLvru/AGD2nv7L31zuzs+LbpqLk/um2Oprv1ZrHk5+m028y22+m0vDXz37vlthmPyurP2eZ6yasfPY1HPo1HufzI2vEotuNRcuXF5LLjZMH78iv/iQx2ylPweEN8CYvlf451oWRKFtk4Fn8Ie6asx3JaRC4O1sDUykbOsoEDkTVlfOVlk0zZSZwsSKhDPZY0vhSaSmguESHU70py4EvloJA0IXn5nHGiJC6lAkbxDnUAgLF1NegDowYQhoQKwJDv0TL+KImHig0paVyupAXVeqyRDKnnpay6JAscDDK8UfYT1RerzBBJGSjOh1pkrYJa7Q2qCH4fllTptDgJstoY7Rkw58qzFWUwGzgdZEevnEIi6CTjkZNDhYhcHAjUrA0gQa1oCXeDJC8yQIopCpHSevQvCju9zLhUEUT6q3AmGhG+AoIG8J0PlUOjwBHCnNjaJwgJAsJ5uppEFoK0rLioX4OZXA/HB24gdJB9hQuYaGkKCgucco+Ju5j1KZF2DT1lilNdpF5MprLeL4FolMjtQjIeA5FZ+HRX5v7oXz2BByDJiOSqE/KqBx4twUYakOOefGR09nmSfol18GbY9wSZMCuVo0VRtS9IWu09ybwJYUHZYPZJBzOQwPzNOOmebf8bsFcsSfSs8+rEE5hi9ss6AElVG6pzJFEwVA0hDbLSUbeqz2j/4gLDKq5FOkSklWAOkM1pdsapWAXs5X+jhXtUyxfD8VouW0Q/KF6OZIdrVYLifanXIenoJnVaM7gVntEtVz0t9VIABbJcG6ny8pJKzbQ6k2pFC3O151FdR0csqvtn9XRT7yucFOtO0CJp8EqnKtYaorSAPdbEmqPVe6ZeKYOb71u23Ipu37Kz1jbcZr3985AkFX1b7YP0VsxiFVCByMUNPhT0roBoYtg7N9W7T8K9TpKX9gUalHN5sVl3GJVmu7u6D/2M6N7jN49Oz0YEycx2u6v1/BoCKprpgxqesc6y2GabzzXB8fPDo+np8aHFt9+3/frtpDl89nhSXgvYSfP85OEjvFi8PHmLx0lz/eH96nh78ePqxasv3frru4NX7dmHwwcPJg2ijtaXX5ZXZ8tfO4m++HZ+82N3ffCa8vnLdydPV9ldHNwg+g5nL9afl9tdPX7ZkSu/5Bed6Wg2m3vrZq7IeL6Ydba1cb5qKS1WNs+NczGtOuNbb7MhR9bH1Nzd/QEO2OWF", \n      "device_id": 23, \n      "id": 6, \n      "num_data": 464064, \n      "tid": "gAAAAABcc65MJ0PJrx3iI-xwnUFJkHOEa8JbQWQ3pPh8dLooKLFH9sJuLYeDbHIlNxWbDr512mKnBBFBc2WxoceFgM1MTW_0SA==", \n      "tid_bi": "5802da51d638fc23e6da3fc0c6a0da2046999ffdfccf55b7f3ec020d5d20b79e"\n    }, \n    {\n      "added": -262258, \n      "correctness_hash": "$2b$12$WwnNuG0K6/F.TnHUF4TsgOHX1xs1W1Y9TiR2nOEhhaeSaXWI7boqu", \n      "data": "eJyVVdlOG0EQ/JXVvsYoM7NzRsoDAhRyC0EOEkfW2izgyCgONrkQ/57p7uolj+HB9s5OT09XdVX7tl3Y9klz2+7NtsvV2cDPs9li1W82s1ldtfPf22HTTpr69ke/uhn47edgJ03Ik6aUSZPMpIlx0mQr61g/1nb6ZWi7hnpeULyvi0wLSlI/KVJsRixtW1u/squLVEMCEtAzbTpDofVNrilT/Y0BO5qejiWuwCAZP2UuocP1Dpfl+htqCSVrrHGSN1lBw88J9VlbpCbBgGwpSBiAGzlAmLMZ0XW4xNBttE1sJZTrJBGhBHFRQBQgtdbhrXAa8JCTfGTf1a+cQRBjpFpD1KOWWHRyP8XlKBiz18MWpSYLKugwhVG51OBcwIJUZSU0JNkdO2q8ZC1JGcljR0gqRltpExiiuqiPqQih3A06TvkJIp2hTZJDgK44B93juawAInIA8gClUR4im6WEHNzYCOAJeQKTn3CM3gglXGoEdBamxgiwjC3qIjPqtPlRkkbtPdUkaosCmBglATAVBUywujuhPyhr1lncxXCFPwe1G6fWyVI44/OSsph/8Fp4l1srQvpyV02+978DgG6nAUCHSYkENKFQQVIgAdhPBSg+zcIG9wQmyFH1qggpT4IcRO0JfseUYdMFKMwU9TXmEN8ZUV+0gu83A7Q7rnsoUraDhQAFGbsEk0rlzxCi8g+Tc3GsbCtgucdRekyN4eEocy3920ieeTALqTDptQHMsY078M28VKCCdP1gqNQ8nupZFdepCwJ0MjqXhxmqo8pIABEWZUWKNzFJI7KyH0QVmKBehyJJ34NnLsRhGCrLMtA9rN3pSEZ1zFR3Px54rmJo8XQ0QXvhMF2MzjHxtiyhRK9OYbIxyYJVt3Qq0U7C2Kv6D2M1hHghr2f9H2Q+ZATSE4ua/05UwPpfhGnj1C/jMbaQHS8xUoKHl8gxEVNaihSuE/ppgv4xEI+sodEf99JZf1stF2SUdrO9fkICauzOs3cHxyeNJc302+31cn5DCqqiGYNadtjCsdr61YUmOHy9uzc7Ptx1dPZqM76/nba7r55N67KWNm1fv90/oIWjxfP39DhtP31Nl4ffj398O3pxuF9Or07e+I+Pj54+nbYUtbdcXw7XJ8OvrUSfro/ch9XlzaOb538u1sufV+Hl5WaXou/o7rPlxbDZ6vXx3PVDl+bZ9QufuqEMbrHwzrvhPLruPJhofAn9kPNZiqULwc+D771fzF3uh+Lbu7u/8cvhIg==", \n      "device_id": 23, \n      "id": 26, \n      "num_data": 459731, \n      "tid": "gAAAAABcVC9y-Abn8uvuN1lGCW7qvdGY2IHfsrl3zCIOP7FDa01oDvBy-vc3gRbuNdA2Elrko2Kahqdg5oagdGkVF6VnO02msw==", \n      "tid_bi": "$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI."\n    }\n  ], \n  "success": true\n}\n'
        with mock.patch('requests.get', return_value=r):
            result = runner.invoke(cmd.get_device_data_by_num_range, [device_id, "--lower", 459679, "--upper", 465192, '--token', access_token])
            assert "failed correctness hash test!" in result.output
            assert "Attribute padded incorrectly." in result.output

    cmd.fake_tuple_data = None


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_slice_by_range(reset_tiny_db, col_keys):
    insert_into_tinydb(cmd.path, 'device_keys', col_keys)
    lower = -1000
    upper = 1000
    result = cmd.slice_by_range([{'added': -959, 'num_data': -980, 'data': '1000', 'tid': '2'}, {'added': -959, 'num_data': 1700, 'data': '1000', 'tid': '2'}], lower, upper, "device_data:num_data")
    assert result == [{'added': -959, 'num_data': -980, 'data': '1000', 'tid': '2'}]


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_send_key_to_device(runner, access_token_two, reset_tiny_db):
    device_id = '45'
    device_id_2 = '34'

    result = runner.invoke(cmd.send_key_to_device, [device_id, '--token', access_token_two])
    assert "Blind index key for device name is missing" in result.output

    insert_into_tinydb(cmd.path, 'device_keys', {
        "device_id": device_id,
        "bi_key": 'fe65ae5d8665d9b68d8e20dec8fca3da23a881e5df60a132a92882a8c666149a'
    })

    insert_into_tinydb(cmd.path, 'device_keys', {
        "device_id": device_id_2,
        "bi_key": '873addb8304b8c96eba645f563aa5b34f2ca2aeadbef1b2291a60a1862e899fb'
    })

    result = runner.invoke(cmd.send_key_to_device, [device_id, '--token', access_token_two])
    assert "\"success\": true" in result.output
    result = runner.invoke(cmd.send_key_to_device, [device_id_2, '--token', access_token_two])
    assert "\"success\": true" in result.output

    table = get_tinydb_table(cmd.path, 'device_keys')
    doc = table.search(where('device_id').exists() &
                       where('public_key').exists() &
                       where('private_key').exists() &
                       where('bi_key').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 2


def test_check_correctness_hash():
    query_result = [
        {
            "correctness_hash": "$2b$12$h15DOn5o9Lwb/dsgJMhSqew6s1skMN9PyLEGauBhZ6.DHiM4j88aW",
            "device_type_id": 23525,
            "id": 23,
            "name": "my_raspberry",
            "name_bi": "a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df",
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
        "name_bi": "a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df",
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
    doc = table.search(where('public_key').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1, "More than one public key."


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_aa_keygen(runner, attr_auth_access_token_one, reset_tiny_db):
    result = runner.invoke(cmd.attr_auth_keygen, ["'1-TODAY 1-GUEST'", '1', '--token', attr_auth_access_token_one])

    assert "Public key not present, please use: get-attr-auth-keys" in result.output
    runner.invoke(cmd.get_attr_auth_keys, ['--token', attr_auth_access_token_one])
    result = runner.invoke(cmd.attr_auth_keygen, ["'1-TODAY 1-GUEST'", '1', '--token', attr_auth_access_token_one])
    assert "\"success\": true" in result.output


@pytest.mark.parametrize('reset_tiny_db', [cmd.path], indirect=True)
def test_aa_device_keygen(runner, attr_auth_access_token_one, reset_tiny_db):
    device_id = "23"
    result = runner.invoke(cmd.attr_auth_device_keygen, ["'1-55 1-GUEST 1'", device_id, '--token', attr_auth_access_token_one])
    assert f"attr_list argument should contain device_id ({device_id})" in result.output

    attr_list = "'1-23 1-GUEST 1'"
    result = runner.invoke(cmd.attr_auth_device_keygen, [attr_list, device_id, '--token', attr_auth_access_token_one])

    assert "Public key not present, please use: get-attr-auth-keys" in result.output
    aa_keys_doc = {
            "public_key": "eJyVVsuO2zAM/BUjZx9EWc/+SrEw0iLNHnIokLZAsci/V0MO5WxPu4ckth4UZzhD5e10PX1Z3k77/v12vt/3fbydvv39dbmf1mWM/jnffl909Gvq65LbutRtXSSMrxbGg5R16XWMyrqUihnBaMJXHMPF1uG34h1LZERBtDaCFERsGNzsIYt9KkKEekSX0PhVM9ZnRtLFiFYwMB5K5kdeHgPENX4UYQ5EGC2ASLWckIuBGy9NeLC+ZeLW04E9bQYMe7KQhpbImYRgsRG2g9HxjHMlRu6LNlEDzx2BM2Jmi60L7WjNiNGrnk9SW7VDkBR+EzHkZHFKx+KZE2qoQ0IgDeiiMDPR0NkKCfTd8cp/BQeeyB2VeLoz1bxqWtDEkitFIMXzahMVTukEXhkehbYtmftMDBoucEO103VAJWTkNJvWl8gSA06RqZXXz5oBlCDrnJwOcUBKQLRKl3r8An4uxpSKCpxUviBBiYHJJ8JXtLovTe2xDorPmK+E3pzAxgIjQQL88Wm3F8oneqn15EDnduLqhkmf6WjUzPGmzlQ6i9CZLPgDEVA4TN7c9Tk8iUSFTXoj6chevcPpl/163c+3n6/nDzteDKW6PVDw1myiZa1JiTUulzOs6Qmb/Mq70ryXZvchXeUmAHOwM/hF5XStWi6auUBnYvHU4KTU/D+7n/WdzTLXHGx+GsZJq+6OyFJ1ikxtEF1N2wyeqCBxBoIloIaOVKfOJm8XxRt7M7KUhTS7RXtqq3lzJwpt2Y4+xwxc3s3VFqw1cppdVLvpbIzq+egtSeUWrWV4c20kw2+scuCuc694QRm8U7NGEiNrDTsr68cwuW1Klzpl+ydLQAm02dVtNm+EoeKmShrvtuq9uBQWoNI4ei0EOsoukuoVzGwM3uy76zLwiOYCwYwV3O9ovXoCRWvpT0Fs5MHdj7VgUvt/KIbSrqnINLx5JMc86VLHxfB0dbsylEOPnVxAkf8R5l1hd5RMl9WXx+Mfq/O0uQ=="
    }
    insert_into_tinydb(cmd.path, "aa_keys", aa_keys_doc)
    insert_into_tinydb(cmd.path, "device_keys", {'device_id': device_id, 'shared_key': "dummy_value"})
    runner.invoke(cmd.attr_auth_device_keygen, [attr_list, device_id, '--token', attr_auth_access_token_one])
    doc = search_tinydb_doc(cmd.path, 'device_keys', Query().device_id == device_id)
    assert "device_data:data" in doc and 'shared_key' in doc and "device_id" in doc
    assert "private_key" in doc["device_data:data"]
    assert doc["device_data:data"]["attr_list"] == ['1-23', '1-GUEST', '1']


def test_aa_encrypt(runner, attr_auth_access_token_one):
    result = runner.invoke(cmd.attr_auth_encrypt, ["Hello World", "(GUESTTODAY)", '--token', attr_auth_access_token_one])
    assert "\"success\": true" in result.output
    assert "\"ciphertext\": " in result.output


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_device_init(runner, reset_tiny_db):
    runner.invoke(device_cmd.init, ["23", "test_password", "name_1", "name_2", "name_3", "name_4"])
    table = get_tinydb_table(device_cmd.path, 'device')
    doc = table.search(where('id').exists())
    assert doc is not None, "Keys not present in DB."
    assert len(doc) == 1
    assert int(doc[0]['id']) == 23
    assert len(doc[0]['actions']) == 4


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_device_receive_pk(runner, reset_tiny_db):
    data = "{'user_public_key': '-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8z5FnI9EoJZmxSXmKItAvZcdL/bjd4VM\nI2KCZU5gud4R034+VKfy0ameLSty3ImUzoOCClkXAvSBqIe+qKRuteGBeCrnVaIV\nWyk8DgOt4Y2Pp3W9Tm/5dRdxxl8RkCg7\n-----END PUBLIC KEY-----\n', 'user_id': '1'}"

    result = runner.invoke(device_cmd.receive_pk, [data])
    table = get_tinydb_table(device_cmd.path, 'users')
    doc = table.search(where('id').exists() & where('shared_key').exists() & where('tid').exists())
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
    assert "public_key" not in doc and "private_key" not in doc, "public_key and private_key should not be present anymore (Ephemeral keys need to be wiped)."


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
                'seed': 1,
                "lower_bound": 1,
                "upper_bound": 1,
                "type": "OPE"
            },
            "num_data": {
                'seed': 2,
                "lower_bound": 1,
                "upper_bound": 25,
                "type": "OPE"
            },
            "data": {
                'seed': 3,
                "lower_bound": 1,
                "upper_bound": 43,
                "type": "ABE"
            },
        }
    }

    result = device_cmd.increment_bounds(table["device_data"])
    assert result["added"]["upper_bound"] == 2
    assert result["num_data"]["upper_bound"] == 26
    assert result["data"]["upper_bound"] == 44


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_get_bi_key_by_user(reset_tiny_db, col_keys):
    user_id = 1
    bi_key = "9ef5134c75a6745507be61bcb44a909bcb0e9d792980b2394862ee73fc359418"

    data = {
        "id": user_id,
        "bi_key": bi_key,
    }
    insert_into_tinydb(device_cmd.path, 'users', data)

    assert device_cmd.get_bi_key_by_user(user_id) == bi_key


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_get_fake_tuple(runner, reset_tiny_db, integrity_data, col_keys):
    user_id = 1
    device_id_doc = {"id": "23"}
    bi_key = "9ef5134c75a6745507be61bcb44a909bcb0e9d792980b2394862ee73fc359418"
    data = {"id": user_id,
            "bi_key": bi_key,
            "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "action:name": "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d",
            "device_type:description": "2c567c6fde8d29ee3c1ac15e74692089fdce507a43eb931be792ec3887968d33",
            "device_data:added": "5b27b633b2ea8fd12617d36dc0e864b2e8c6e57e809662e88fe56d70d033429e",
            "device_data:num_data": "ed1b6067e3dec82b4b61360c29eaeb785987e0c36bfdba454b9eca2d1622ecc2",
            "device_data:data": {
                "public_key": "eJyVVstuGzEM/BXDZx9E7erVXykCwy1S55BDgbQFiiD/Xg05Izs9JQd711yJOzMcUn49Xo9fDq/H8/n78+Xl5Xyev47f/v56fDmeDjP65/L8+9GjX/dxOpR+OtR2OvT5afNTbF7LvKbTYZ/PCmJbxM3q/Mrzrs4VtTLS9ti+NwTm2jrzIrcZojPQ8+1qKccWX55TLG0z2DufWvK7wk0WGas9vE0G1/xReqAAek5NYC3xV98i/XDUO1kCRgIugEx88QTSwXHEIksjtkEvPLCEfDVWW5qRNmI78oFaaNVC0tpJvIkrKHZfogTAvvQoheCRBvCAHagg4RiE67BWDRCG3AAMASwZl3gBfR0U7qj1rrKAekpkloVlC+6wySBlXyAenghkysQ3SAyJoTOSo9zAC1m6k0lClBcsvNcXbUF0F9YiIK6z1yq2RRYt8zLhassrT5/thC6X+8sD1ha1aV3uLkEIYnnRIL5Xooc2UQOsMvWNMSKMnlAidVbAcijmbWfLDa5X5/ve98KPz/KDtk6i0Br4IHE0Y6a8Ts/CRHCiW7epe7xSfWmzCWQ4bFM70RNNnig3dfDbTWmN5EJrKP8fxcfz9Xq+PP98uny47S24EtTO8SOzRvdl6uBfoNpX52ksFU6ywobzIGq880FtmldOAwzQnAh7/xvvdw0Gi+zeQ6vbXdpOf2EYVM6O5SskKFVj0TRO0Az7RmMVmpJFyGsmpADlBsscw9FMeHFlcSLh0DgSp6bpnjXo1sS73+Tnx1B/IoNDvvVpDedpKuIaji/qNGG9ez/VHhpe+80renFXS5Glr2tqNk9RqsSud10J6BhhMINvjKdZFJvUHHcah2EyzV/UIxwb3jM55IxDhnX3ocdzrDRN4xIP8fKm6b+C9R5CpnBCUHk6u6LqNnppnRr1dqy6hSh0YSG9G8DZzzOMJ9wMuY7e4fFQdcI0TVllzWwXNL0OQz+svDh9je32bpglzW7/b1FvR0eTSuuvwhb6xim4Pby9/QMmWbTA",
                "policy": "1-23 1-GUEST 1"
            },
            "device_data:tid": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "scene:name": "7c2a6bb5e7021e30c7326bdb99003fd43b2b0770b0a4a07f7b3876634b11ff94",
            "scene:description": "d011b0fa5a23b3c2efadb2e0fea094647ff7b03b9a93022aeae6c1edf3eb1871"}

    insert_into_tinydb(device_cmd.path, 'users', data)
    insert_into_tinydb(device_cmd.path, 'device', device_id_doc)

    with mock.patch('client.device.commands.init_integrity_data', return_value=integrity_data):
        result = runner.invoke(device_cmd.get_fake_tuple, [str(user_id), "upper_bound"])
        table = get_tinydb_table(device_cmd.path, 'users')
        doc = table.get(Query().id == user_id)
        assert "integrity" in doc, "Integrity sub-document wasn't inserted."
        assert all(val in doc["integrity"]["device_data"] for val in ["data", "num_data", "added"])

        search_res = re.findall('\"(tid_bi|tid|data|num_data|added|correctness_hash)\": \"?([^:,\"]+)\"?', result.output)

        assert len(search_res) == 6

        column, ciphertext = next(pair for pair in search_res if pair[0] == "data")
        plaintext = decrypt_using_abe_serialized_key(ciphertext, data[f"device_data:{column}"]["public_key"], col_keys[f"device_data:{column}"]["private_key"])
        assert plaintext == pad_payload_attr("-126235597")  # mmh3.hash(str(1), 3)

        column, ciphertext = next(pair for pair in search_res if pair[0] == "tid")
        plaintext = decrypt_using_fernet_hex(data[f"device_data:{column}"], ciphertext)
        assert plaintext.decode() == "1"

        column, tid_bi = next(pair for pair in search_res if pair[0] == "tid_bi")
        assert blind_index(hex_to_key(bi_key), "1") == tid_bi

        result = runner.invoke(device_cmd.get_fake_tuple, [str(user_id), "upper_bound"])
        search_res = re.findall('\"(tid|data|num_data|added|correctness_hash)\": \"?([^:,\"]+)\"?', result.output)

        assert len(search_res) == 5

        column, ciphertext = next(pair for pair in search_res if pair[0] == "num_data")
        plaintext = decrypt_using_ope_hex(data[f"device_data:{column}"], ciphertext)
        assert plaintext == -623552190  # mmh3.hash(str(2), 2)

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
        assert plaintext == 875522973  # mmh3.hash(str(1), 2)

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

    data = {"id": user_id,
            "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "integrity": {"device_data": {
                "added": {'seed': 1,
                          "lower_bound": 12,
                          "upper_bound": 11,
                          "type": "OPE"},
                "num_data": {'seed': 2,
                             "lower_bound": 12,
                             "upper_bound": 11,
                             "type": "OPE"},
                "data": {'seed': 3,
                         "lower_bound": 12,
                         "upper_bound": 11,
                         "type": "ABE"}}}}

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

    json_data = json.loads(result.output)

    decrypted = decrypt_using_fernet_hex(data["shared_key"], json_data["device_data"])
    fake_tuple_info_dict = json_string_with_bytes_to_dict(decrypted.decode())

    assert fake_tuple_info_dict == data["integrity"]["device_data"]


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_process_action(runner, reset_tiny_db, col_keys):
    payload_no_user = '{"not_user_id": 99}'
    payload = '{"user_id": "u:1", "action": "gAAAAABcXcF9yNe9emKXALJImsb7v4meic8cR6YnEulQSi8xOxF8d33scDotxPKQBTC80r-QolW2mRroUZOfLuqAqr20Z5333A=="}'  # b'On' encrypted with col_keys["action:name"]
    insert_into_tinydb(device_cmd.path, 'users', {"id": 1, "action:name": "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d"})

    with pytest.raises(Exception) as e:
        runner.invoke(device_cmd.process_action, [payload_no_user])
        assert e.value.message == "No user with ID 99"

    result = runner.invoke(device_cmd.process_action, [payload])
    assert "On" in result.output


@pytest.mark.parametrize('reset_tiny_db', [device_cmd.path], indirect=True)
def test_get_next_tid(reset_tiny_db):
    user_id = 1
    insert_into_tinydb(device_cmd.path, 'users', {
        "id": user_id,
        "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
        "tid": -5
    })
    assert device_cmd.get_next_tid(user_id) == -5

    doc = search_tinydb_doc(device_cmd.path, 'users', Query().id == user_id)
    assert doc["tid"] == -6


def test_encrypt_using_abe_serialized_key(col_keys, aa_public_key):
    pk = aa_public_key
    result = encrypt_using_abe_serialized_key(pk, "Hello", "(Owner)")
    assert isinstance(result, str)

    with pytest.raises(Exception) as e:
        encrypt_using_abe_serialized_key("INVALID", "Hello", "(Owner)")
        assert e.value.message == "Invalid public key."


def test_decrypt_using_abe_serialized_key(col_keys, aa_public_key):
    pk = aa_public_key
    sk = col_keys["device_data:data"]["private_key"]
    ciphertext = encrypt_using_abe_serialized_key(pk, "Hello", "(1-23)")

    result = decrypt_using_abe_serialized_key(ciphertext, pk, sk)
    assert result == "Hello"

    with pytest.raises(Exception) as e:
        decrypt_using_abe_serialized_key("INVALID", "INVALID", "INVALID")
        assert e.value.message == "One of the serialized objects is invalid."


def test_pad_payload_attr():
    with pytest.raises(Exception) as e:
        pad_payload_attr(" " * 300)
        assert e.value.message == "Attribute value too long."

    assert len(pad_payload_attr("data")) == 256
    assert pad_payload_attr("data").strip() == "data"


def test_unpad_payload_attr():
    with pytest.raises(Exception) as e:
        unpad_payload_attr(" " * 300)
        assert e.value.message == "Attribute padded incorrectly."
        unpad_payload_attr(" ")
        assert e.value.message == "Attribute padded incorrectly."

    assert len(unpad_payload_attr(pad_payload_attr("data"))) == 4


def test_unpad_row():
    row = {"data": pad_payload_attr("data"), "another": "dummy"}

    assert unpad_row("data", row) == {"data": "data", "another": "dummy"}


def test_broker_username_to_id():
    invalid_username = "ergedrg:"
    username = "u:3"
    with pytest.raises(Exception) as e:
        device_cmd.broker_username_to_id(invalid_username)
        assert e.value.message == f"Invalid user ID: {invalid_username}"

    assert device_cmd.broker_username_to_id(username) == "3"
