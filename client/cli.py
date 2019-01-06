#!/usr/bin/env python

import click

from user import commands as user_cli
from device import commands as device_cli

VERIFY_CERTS = True


@click.group()
@click.option('--debug/--no-debug', default=True)
@click.pass_context
def cli(ctx, debug):
    ctx.obj['VERIFY_CERTS'] = not debug
    if debug:
        click.echo("YOU ARE RUNNING IN DEBUG MODE - CERTIFICATES ARE NOT BEING VERIFIED.")


cli.add_command(user_cli.user)
cli.add_command(device_cli.device)

if __name__ == '__main__':
    cli(obj={})
