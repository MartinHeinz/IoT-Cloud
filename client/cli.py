import click

from user import commands as user_cli
from device import commands as device_cli


@click.group()
def cli():
	pass


cli.add_command(user_cli.user)
cli.add_command(device_cli.device)

if __name__ == '__main__':
	cli()
