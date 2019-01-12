#!/usr/bin/env python

import click

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

if __name__ == '__main__':
    cli(obj={})
