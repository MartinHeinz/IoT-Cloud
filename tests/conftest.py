import os
import warnings
import pytest
from click.testing import CliRunner
from sqlalchemy.exc import SADeprecationWarning

from app.app_setup import create_app, db


@pytest.fixture(scope="module")
def runner():
    return CliRunner(echo_stdin=True)


@pytest.fixture(scope="module")
def client():
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app(os.getenv('TESTING_ENV', "testing"))
    return app.test_client()


@pytest.fixture(scope="module")
def app_and_ctx():
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app(os.getenv('TESTING_ENV', "testing"))
    ctx = app.app_context()
    ctx.push()
    yield app, ctx
    db.drop_all()


@pytest.fixture(scope="module")
def application():
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app(os.getenv('TESTING_ENV', "testing"))
    yield app
    db.drop_all()


@pytest.fixture(scope="session")
def access_token():
    return "5c36ab84439c45a3719644c0d9bd7b31929afd9f"


@pytest.fixture(scope="session")
def master_key_user_one():  # `b'...'.decode("utf-8")`
    return 'eJydVUFuGzEM/MrCZx9W0oqUemu/URhGWgQp0NzcFgiC/L0acqjd9hTnkGAtiSJnOBy9np5On5bX0/X6/fnhdrtex6/Tt5dfj7fTeRmrfx6efz/a6tetn5fazksr50XH96bnJaV8XvpYrAU/xkpb8TG2Zfzp+CFjN61jp2Nnxdnx0eq4AJcJFkdwy4izI2OrVgYpz+OmmsYxFGExnQvjR0XeDfHtkFzS5W1g+PFefEgDfH3cJrh13ChEhG9ks/oFxeXEf22sqDoLKMZhCvnJRseI1sKijT7xFCkVD9RG9KABN/RO3Ngc4U0Z1QkTKUGGsZSSOJ3WBtBZddK5OgTA0uyta7yxjfrRVuxjD3A3RjeWNsuzi6zoxBqR0NpWZzIl+LRuZC0zlYQUMjc2r0MCSFLercpsQCOkVFMs5mj0Sq6gB2sOxAhIugYlnUwgEMCtp9VPSZoaebr+hALuGgOA2YxuZKz8SJl4oWBkczZSPlTkesj88D1gsVhXmZJVb2OJsRIue+OL91yUoldeu7UgsjrafRruQmigcp5iX1kLirIOqqtqDqvNsGk88zy6VilrDWewQavORe+ceJOf+IUONPSmEtxCIa6DEJPNev0wOiTD/FqzxHVuo1/DYYpnhFDRbJ/i7P7lqkoxHsRtmjCaZNdbJNs7a0dc0CnAZAfcyn8udhkYPr9foI0+XekS2QWDdZMfkk7rajRY12qd1c3+p4O6XOthLS7hQstDhKUW2qTj4SvgUxhN9DOhznRf/wKe7H7mfMcPqAMZzM1a5J2lr+HjptD94ZKwT1quhAUXbmS+QyC0kthK/3FttsNcHy0GDfxydwOFj0jbNSNhoJyNFsy7zWS+HJ3Ps7Wdft85de6zTkKObnaXy7TG7ufNyAqz2wWkwG0ufbx5xS/vPUYpx9TRtzRMZvfJ4kcQa0+wVS1+VKODx4cao9jaFDFnzSVROIwaHGDFH6j2ry4vb38B5pjYKQ=='


@pytest.fixture(scope="session")
def master_key_user_two():  # `b'...'.decode("utf-8")`
    return 'eJydVstu3DAM/BVjz3uQbFGiemt/o1gs0iJIgeaWtkAQ5N8rDoeyF71ke0hiyxQfM0Myb6en06fl7XS9fn9+eHm5Xsfb6dvrr8eX03kZp38enn8/4vRr6edF9LxUOS9tPS852UEZD3n+Stv4luxhGHS14+Q3dLwIvig/ty2ub/5J1t20iVmNr2Uzi8w3xOwWF9+bR5te3GbNzKQOw5ov76OSHx+tEolYApbmijIr4+p40NVT6iN0QX3Cr6145gaTFndQh5WK34SRXbXSWrcDYbJtm2FKnGcLncdZGT7k8BeIwplhZenWSggSvI4TTR4fVFgRkp0OzY6KpU+c1LMq8wT2KeCdXFQvSzYnAN7qkU9kW2VKod8YmMPcPLrQMUhcWQFMzHtrDiIYSNRD1ai+srw+dTFiKz27WrbAFReON3s/5GnoGPT2jJ885fJ0/WliuKsvVP9RKsBSZ8eiGYAoLZNHpcIbpQ80kKSxUAMjQCPB57isncD6523vJjsQYqSMYOiAeYkC7yoM/llZj9gbyTG2csrevaCOOm3lQEsjEY4R2OjBT+IRZgqi4C27ap3NHEKG1lPI3Jjfok/N497x91EnLAsKre4HuVhSciQH5HoZhT3SE9+0MQ0AHghhpIln2/cJqA6XO16j72Tis2O+j4O+c3gZtXz+uEZ1LxTdvnkRKpOBRIoAfHIIMKo0xlXyhjYDABDzAU2XphPTpzQ2pkmyh6ZzKBfVzF2BxuQ4gUzzfSRGbW22XqbkIFcK3xqkx2qqMdJ67JPVp7U5q8zDqjcUHCS2MqqPtaCxhWQLUbAVdZ/U4k3oGynv7H25n718s5dC/Tlmq7AnsJQsJgbIygnuYgoTA6rttxNZ6Zy1Xpn6pqiUAdwRGA2qcQ3zq4dE/5O/wjKQm7C6FgvFEvCgKXTDfy0klo9zsrptKMrT4m6Zy01vWtnuleM0xS+d4uwuneOSuLz/BWOA29Y='


@pytest.fixture(scope="session")
def attr_auth_access_token():
    return '54agPr4edV9PvyyBNkjFfA))'

