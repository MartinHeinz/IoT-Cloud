import base64
import click
import requests
from crypto_utils import encrypt, hash  # TODO FIX ME

URL_BASE = "https://localhost/api/"
URL_PUBLISH = URL_BASE + "publish"
URL_CREATE_DEVICE_TYPE = URL_BASE + "device_type/create"
URL_CREATE_DEVICE = URL_BASE + "device/create"
URL_GET_DEVICE = URL_BASE + "device/get"
URL_GET_DEVICE_DATA_BY_RANGE = URL_BASE + "data/get_time_range"


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
    data = {"description": description, "access_token": token}
    r = requests.post(URL_CREATE_DEVICE_TYPE, params=data, verify=False)
    click.echo(r.content.decode('unicode-escape'))


@user.command()
@click.argument('device_type_id')
@click.option('--token', envvar='ACCESS_TOKEN')
def create_device(device_type_id, token):
    data = {"type_id": device_type_id, "access_token": token}
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
    click.echo(r.content.decode('unicode-escape'))


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
    click.echo(r.content.decode('unicode-escape'))


if __name__ == '__main__':
    # json_data = json.loads(create_device_type("test desc").content.decode("utf-8"))
    # print(json_data)
    # print(create_device(json_data["type_id"]).content.decode("utf-8"))
    send_message()
