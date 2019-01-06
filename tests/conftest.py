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
    return 'eJyNUstOxDAM/JWo5x7iNC/zKwhVXVTBoQekLkhotf+Ox45hjxzSJs7Enhn7Nl326zY9hdu0rq/Hdp7rKqfp8n3dz2kOEv3ajs9do8+5z6HIqnUOlEgO2MQ0h8ZyyHMAohYJEm5l0+UyN9' \
           'njLyCWfYsAMJ42fBaBIdwMSkmwlUcSgJkts9ZUCB42ibQM2IKIUumeFOkrYb3cRcZbWrfj4/3fSks0peDVQRuUowobUYpSupdBl6LUYhCSQ19Mb1uMegcrGoxhSqEhMEV71avpqm4KbIKf' \
           'FfUF1LOn4V+Z2RsRByMQUcJlWNXkunpx7RPagWLMI4oMxdupHkOJnpAGUoiSNRW0G5muohfV3HloZlKjogMWGw0lUuxf/BGgelEtbfcuR7eouGhQivwwItSHDXAMliqWjTCS/TmTbfB8EN' \
           'UGtBcBomxPdY1xuf8AJSqbbw=='


@pytest.fixture(scope="session")
def master_key_user_two():  # `b'...'.decode("utf-8")`
    return 'eJyNUrtuwzAM/JXAcwZRFiWqv1IUhlMY7eChgNMCRZB/D4+kUGTrQJmijo87+jZdtus6vZxu07K87+txLIvepsvvdTum80mjP+v+vVn0tcj5xGqUEo6qB+nRzMnqdDV9ErWuVqv7PKvfAN' \
           'KjqLFaY9QQz2K9SAYCJQoccUdq5BFRdAB2jgArpOlrRxHc0VK/1eztrhQ+8rLuX5//ZsnJWfo8eojWlxJjsEUVUmaPoiuGbOJIkG0ApfIXdLHSPMIUGFMNQmTyhsbdVEGmuI488tCvxEOb' \
           'Q/4a6OiRvDT20ELVOnYmGgA9ouIFDBEkbDxA2TbTXFyOIGXjRJ6DIl1iX1iGse6D0ROJ2JK/zC4c5eRM6li+uIo9YrWPJWN+Hk5wp9S9sAlZne34FRAvPWZsrgbukkIF+zX5+T+5PwBHm5k5'


@pytest.fixture(scope="session")
def attr_auth_access_token_one():
    return '54agPr4edV9PvyyBNkjFfA))'


@pytest.fixture(scope="session")
def attr_auth_access_token_two():
    return '7jagPr4edVdgvyyBNkjdaQ))'
