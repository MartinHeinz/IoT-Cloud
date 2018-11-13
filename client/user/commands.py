import base64
import click
import requests

from crypto_utils import encrypt

URL_BASE = "https://localhost/api/"
URL_PUBLISH = URL_BASE + "publish"
URL_CREATE_DEVICE_TYPE = URL_BASE + "device_type/create"
URL_CREATE_DEVICE = URL_BASE + "device/create"


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
    click.echo(r.content)


@user.command()
@click.argument('description')
def create_device_type(description):
    data = {"description": description}
    r = requests.post(URL_CREATE_DEVICE_TYPE, params=data, verify=False)
    click.echo(r.content)


@user.command()
@click.argument('device_type_id')
def create_device(device_type_id):
    data = {"type_id": device_type_id}
    r = requests.post(URL_CREATE_DEVICE, params=data, verify=False)
    click.echo(r.content)


if __name__ == '__main__':
    # json_data = json.loads(create_device_type("test desc").content.decode("utf-8"))
    # print(json_data)
    # print(create_device(json_data["type_id"]).content.decode("utf-8"))
    send_message()
