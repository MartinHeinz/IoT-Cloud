import os

basedir = os.path.abspath(os.path.dirname(__file__))
config_path = os.path.join(os.path.abspath(os.path.join(__file__, "../..")), 'config.env')

if os.path.exists(config_path):
    print('Importing environment from .env file', flush=True)
    for line in open(config_path):
        var = line.strip().split('=')
        if len(var) == 2:
            os.environ[var[0]] = var[1].replace("\"", "")


class Config:
    DEBUG = True
    APP_NAME = os.getenv('APP_NAME', 'IoT-Cloud')
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True

    TRAP_HTTP_EXCEPTIONS = True

    MQTT_BROKER_URL = os.getenv('MQTT_BROKER_URL', 'localhost')
    MQTT_BROKER_PORT = int(os.getenv('MQTT_BROKER_PORT', '1883'))
    MQTT_USERNAME = os.getenv('MQTT_USERNAME', '')
    MQTT_PASSWORD = os.getenv('MQTT_PASSWORD', '')
    MQTT_REFRESH_TIME = 1.0  # refresh time in seconds
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    CA_CERTS_PATH = os.path.join(os.path.dirname(__file__), "..", "resources/certs/server/server.crt")
    SSL_INSECURE = True  # Needed to avoid "ssl.CertificateError: hostname '<host ip>' doesn't match '<Name on cert>'"

    CLIENT_CERTFILE_PATH = None
    CLIENT_KEYFILE_PATH = None

    POPULATE_PATH = os.path.join(os.path.dirname(__file__), "..", "populate.sql")
    ATTR_AUTH_POPULATE_PATH = os.path.join(os.path.dirname(__file__), "..", "attr_auth_populate.sql")

    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID', 'missing-id')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET', 'very-secret')

    STACKOVERFLOW_CLIENT_ID = os.getenv('STACKOVERFLOW_CLIENT_ID', 'missing-id')
    STACKOVERFLOW_CLIENT_SECRET = os.getenv('STACKOVERFLOW_CLIENT_SECRET', 'very-secret')

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    ASSETS_DEBUG = True
    ENV = 'development'
    SQLALCHEMY_DATABASE_URI = os.getenv('DEV_DATABASE_URL', 'postgres+psycopg2://postgres:postgres@<local-ip>:5430/postgres')
    SQLALCHEMY_BINDS = {
        'attr_auth': os.getenv('DEV_DATABASE_ATTR_AUTH_URL', 'postgres+psycopg2://postgres:postgres@<local-ip>:5430/attr_auth'),
    }
    print('THIS APP IS IN DEBUG MODE. YOU SHOULD NOT SEE THIS IN PRODUCTION.')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv('TEST_DATABASE_URL', 'postgres+psycopg2://postgres:postgres@db_test/testing')
    SQLALCHEMY_BINDS = {
        'attr_auth': os.getenv('TEST_DATABASE_ATTR_AUTH_URL', 'postgres+psycopg2://postgres:postgres@db_test/attr_auth_testing'),
    }
    WTF_CSRF_ENABLED = False


class HostTestingConfig(TestingConfig):
    SQLALCHEMY_DATABASE_URI = os.getenv('TEST_DATABASE_HOST_URL', 'postgres+psycopg2://postgres:postgres@<local-ip>:5430/testing')
    SQLALCHEMY_BINDS = {
        'attr_auth': os.getenv('TEST_DATABASE_HOST_ATTR_AUTH_URL', 'postgres+psycopg2://postgres:postgres@<local-ip>:5430/attr_auth_testing')
    }
    MQTT_BROKER_URL = os.getenv('MQTT_BROKER_HOST_URL', 'localhost')


class DockerConfig(Config):
    ASSETS_DEBUG = True
    ENV = 'development'
    SQLALCHEMY_DATABASE_URI = os.getenv('DOCKER_DATABASE_URL', 'postgres+psycopg2://postgres:postgres@<local-ip>:5430/postgres')
    SQLALCHEMY_BINDS = {
        'attr_auth': os.getenv('DOCKER_DATABASE_ATTR_AUTH_URL', 'postgres+psycopg2://postgres:postgres@<local-ip>:5430/attr_auth')
    }


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'host_testing': HostTestingConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig,
}
