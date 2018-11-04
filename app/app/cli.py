import subprocess
import click


@click.command("populate")
@click.option('--path', default="../populate.sql", help='path sql script that populates database.')
@click.option('--host', default="localhost", help='Host')
@click.option('--db', default="flask_test", help='DB to be populated.')
@click.option('--username', default="postgres", help='Valid Postgresql role.')
def populate(path, host, db, username):
	subprocess.check_output(["psql", "-h", host, "-U", username, "-d", db, "-a", "-f", path, "-W"])
	print("Database populated...", flush=True)
