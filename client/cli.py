#!/usr/bin/env python

import click

try:  # for packaged CLI (setup.py)
    from client import user_cli
    from client import device_cli
except ImportError:  # pragma: no un-packaged CLI cover
    from user import commands as user_cli
    from device import commands as device_cli

VERIFY_CERTS = True

MQTT_BROKER = "172.21.0.3"
MQTT_PORT = 8883


@click.group()
@click.option('--debug/--no-debug', default=True)
@click.option('--broker', '-b', default=MQTT_BROKER)
@click.option('--port', '-p', default=MQTT_PORT)
@click.pass_context
def cli(ctx, debug, broker, port):
    ctx.obj['VERIFY_CERTS'] = not debug
    ctx.obj['BROKER'] = broker
    ctx.obj['PORT'] = port
    if debug:
        click.echo("YOU ARE RUNNING IN DEBUG MODE - CERTIFICATES ARE NOT BEING VERIFIED.")


cli.add_command(user_cli.user)
cli.add_command(device_cli.device)

cli(obj={})


"""
NOTES:
Install package:
1. create venv - `python3 -m venv <absolute-path>`
2. activate venv - source <absolute-path>/bin/activate
    - `which python` should now show _<absolute-path>/bin/python_
3. `cd` into _IoT-Cloud_
`pip install --editable .`

Usage:
In console `iot-cloud-cli user ...`, `iot-cloud-cli device ...`
"""
