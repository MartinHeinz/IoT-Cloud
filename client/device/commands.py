import base64
import click

from crypto_utils import decrypt


@click.group()
def device():
    pass


@device.command()
@click.argument('ciphertext')
@click.argument('tag')
def parse_msg(ciphertext, tag):
    try:
        ciphertext_decoded = base64.b64decode(ciphertext)
        tag_decoded = base64.b64decode(tag)

        key = b'f\x9c\xeb Lj\x13n\x84B\xf5S\xb5\xdfnl53d\x10\x12\x92\x82\xe1\xe3~\xc8*\x16\x9f\xd69'  # os.urandom(32)
        iv = b'HQ\xd9\xb3Kz\n\xcc\xb224Q\xdb\xc7u\xb7'  # os.urandom(16)

        data = decrypt(
            key,
            b"authenticated but not encrypted payload",
            iv,
            ciphertext_decoded,
            tag_decoded
        )
        click.echo(data.decode("utf-8"))
    except:
        click.echo("Incorrect payload.")


if __name__ == '__main__':
    parse_msg()
