import os
import subprocess
import sys
import click


@click.command("populate")
@click.option('--path', default="populate.sql", help='path sql script that populates database.')
@click.option('--host', default="localhost", help='Host')
@click.option('--db', default="flask_test", help='DB to be populated.')
@click.option('--username', default="postgres", help='Valid Postgresql role.')
def populate(path, host, db, username):
    os.environ["PGPASSWORD"] = click.prompt("Postgres Password: ", hide_input=True)
    child = subprocess.Popen(["psql", "-h", host, "-U", username, "-d", db, "-a", "-f", path], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    child.wait()
    return sys.exit(child.returncode)
