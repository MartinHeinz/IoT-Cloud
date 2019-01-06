import base64
import json
import os
import re
from datetime import datetime

import click
import requests
from tinydb import TinyDB, where

from crypto_utils import encrypt, hash, correctness_hash, check_correctness_hash
from utils import json_string_with_bytes_to_dict

URL_BASE = "https://localhost/api/"
URL_PUBLISH = URL_BASE + "publish"
URL_CREATE_DEVICE_TYPE = URL_BASE + "device_type/create"
URL_CREATE_DEVICE = URL_BASE + "device/create"
URL_GET_DEVICE = URL_BASE + "device/get"
URL_GET_DEVICE_DATA_BY_RANGE = URL_BASE + "data/get_time_range"

AA_URL_BASE = "https://localhost/attr_auth/"
AA_URL_SET_USERNAME = AA_URL_BASE + "set_username"
AA_URL_SETUP = AA_URL_BASE + "setup"
AA_URL_KEYGEN = AA_URL_BASE + "keygen"
AA_URL_ENCRYPT = AA_URL_BASE + "encrypt"
AA_URL_DECRYPT = AA_URL_BASE + "decrypt"

dir_path = os.path.dirname(os.path.realpath(__file__))
path = f'{dir_path}/keystore.json'


@click.group()
def user():
    pass


@user.command()
def send_message():
    key = b'f\x9c\xeb Lj\x13n\x84B\xf5S\xb5\xdfnl53d\x10\x12\x92\x82\xe1\xe3~\xc8*\x16\x9f\xd69'  # os.urandom(32)

    iv, ciphertext, tag = encrypt(
        key,
        b"{\"setOn\": \"True\"}",
        b"authenticated but not encrypted payload"
    )

    topic = "flask_test"
    data = {"ciphertext": str(base64.b64encode(ciphertext), 'utf-8'), "tag": str(base64.b64encode(tag), 'utf-8'), "topic": topic}
    click.echo(data)

    r = requests.post(URL_PUBLISH, params=data, verify=False)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('description')
@click.option('--token', envvar='ACCESS_TOKEN')
def create_device_type(description, token):
    data = {"description": description, "access_token": token, "correctness_hash": correctness_hash(description)}
    r = requests.post(URL_CREATE_DEVICE_TYPE, params=data, verify=False)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_type_id')
@click.argument('device_name')
@click.argument('user_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def create_device(device_type_id, user_id, device_name, token):
    data = {
        "type_id": device_type_id,
        "access_token": token,
        "name": device_name,
        "correctness_hash": correctness_hash(device_name),
        "name_bi": hash(device_name, user_id)}
    r = requests.post(URL_CREATE_DEVICE, params=data, verify=False)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_name')
@click.argument('user_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def get_devices(device_name, user_id, token):
    device_name_bi = hash(device_name, user_id)
    data = {"name_bi": device_name_bi, "access_token": token}
    r = requests.post(URL_GET_DEVICE, params=data, verify=False)
    content = json.loads(r.content.decode('unicode-escape'))
    check_correctness_hash(content["devices"], "name")
    click.echo(content["devices"])


@user.command()
@click.option('--lower', required=False)
@click.option('--upper', required=False)
@click.option('--token', envvar='ACCESS_TOKEN')
def get_device_data_by_time_range(lower=None, upper=None, token=""):  # TODO add decryption based on stored keys
    if lower is not None and upper is not None:
        data = {"lower": int(lower), "upper": int(upper), "access_token": token}
    elif lower is not None and upper is None:
        data = {"lower": int(lower), "access_token": token}
    elif lower is None and upper is not None:
        data = {"upper": int(upper), "access_token": token}
    else:
        data = {"lower": 0, "upper": 2147483647, "access_token": token}
    r = requests.post(URL_GET_DEVICE_DATA_BY_RANGE, params=data, verify=False)
    content = r.content.decode('unicode-escape')
    json_content = json_string_with_bytes_to_dict(content)
    for item in json_content["device_data"]:
        item["added"] = str(datetime.strptime(item["added"], "%a, %d %b %Y %H:%M:%S %Z").date())
    check_correctness_hash(json_content["device_data"], 'added', 'data', 'num_data')
    click.echo(content)


@user.command()
@click.argument('username')
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_set_api_username(username, token):
    data = {"api_username": username, "access_token": token}
    r = requests.post(AA_URL_SET_USERNAME, params=data, verify=False)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def get_attr_auth_keys(token):
    data = {"access_token": token}
    r = requests.post(AA_URL_SETUP, params=data, verify=False)
    content = json.loads(r.content.decode('unicode-escape'))
    click.echo(f"Saving keys to {path}")
    db = TinyDB(path)
    table = db.table(name='aa_keys')
    doc = table.get(where('public_key').exists() & where('master_key').exists())
    data = {"public_key": content["public_key"], "master_key": content["master_key"]}
    if doc:
        table.update(data)
    else:
        table.insert(data)


@user.command()
@click.argument('attr_list')
@click.argument('receiver_id')
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_keygen(attr_list, receiver_id, token):
    db = TinyDB(path)
    table = db.table(name='aa_keys')
    doc = table.get(where('public_key').exists() & where('master_key').exists())
    if not doc:
        with click.Context(get_attr_auth_keys) as ctx:
            click.echo(f"Master key not present, please use: {ctx.command.name}")
            click.echo(get_attr_auth_keys.get_help(ctx))
            return
    data = {
        "access_token": token,
        "master_key": doc['master_key'],
        "attr_list": re.sub('[\']', '', attr_list),
        "receiver_id": receiver_id
    }
    r = requests.post(AA_URL_KEYGEN, params=data, verify=False)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('message')
@click.argument('policy_string')
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_encrypt(message, policy_string, token):
    data = {
        "access_token": token,
        "message": message,
        "policy_string": policy_string
    }
    r = requests.post(AA_URL_ENCRYPT, params=data, verify=False)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('owner_username')
@click.argument('ciphertext')  # TODO allow specifying file path
@click.option('--token', envvar='AA_ACCESS_TOKEN')
def attr_auth_decrypt(owner_username, ciphertext, token):
    data = {
        "access_token": token,
        "api_username": owner_username,
        "ciphertext": ciphertext
    }
    r = requests.post(AA_URL_DECRYPT, params=data, verify=False)
    click.echo(r.content.decode('unicode-escape'))


if __name__ == '__main__':
    # json_data = json.loads(create_device_type("test desc").content.decode("utf-8"))
    # print(json_data)
    # print(create_device(json_data["type_id"]).content.decode("utf-8"))
    send_message()
