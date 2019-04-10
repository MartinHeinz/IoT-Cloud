#!/usr/bin/env python
import traceback

import click
import urllib3

try:  # for packaged CLI (setup.py)
    from client import user_cli
    from client import device_cli
except ImportError:  # pragma: no un-packaged CLI cover
    from user import commands as user_cli
    from device import commands as device_cli

VERIFY_CERTS = True

MQTT_BROKER = "172.26.0.8"
MQTT_PORT = 8883


class CatchAllExceptions(click.Group):

    def __call__(self, *args, **kwargs):
        try:
            return self.main(*args, **kwargs)
        except Exception as e:  # pragma: no exc cover
            formatted_lines = traceback.format_exc().splitlines()
            click.echo(f"\nSomething went wrong at in {formatted_lines[-3]}: \n")
            click.echo(f"{repr(e)}\n")


@click.group(cls=CatchAllExceptions)
@click.option('--debug/--no-debug', default=True)
@click.option('--broker', '-b', default=MQTT_BROKER)
@click.option('--port', '-p', default=MQTT_PORT)
@click.pass_context
def cli(ctx, debug, broker, port):
    ctx.obj['VERIFY_CERTS'] = not debug
    ctx.obj['BROKER'] = broker
    ctx.obj['PORT'] = port
    if debug:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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
3. `cd` into venv
4. `git clone https://github.com/JHUISI/charm.git`
5. `cd charm`
6. `./configure.sh`
7. `sudo make install`
8. `sudo ldconfig`
9. `cd` into _IoT-Cloud_
10. `pip install --editable .`

When using with `node-RED`:
11. `cd` into `./node-red`
12. _To test_: ``iot-cloud-cli device --help`

Usage:
In console `iot-cloud-cli user ...`, `iot-cloud-cli device ...`
"""
