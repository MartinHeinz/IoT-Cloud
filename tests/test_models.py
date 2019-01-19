from app.models.models import DeviceType, User
from app.utils import is_valid_uuid
from client.crypto_utils import correctness_hash

from .conftest import db


def test_device_type_uuid(app_and_ctx):
    app, ctx = app_and_ctx

    with app.app_context():
        dt = DeviceType(description=b"nothing", correctness_hash=correctness_hash("nothing"))
        db.session.add(dt)
        db.session.commit()
        assert is_valid_uuid(str(dt.type_id))


def test_can_use_device(app_and_ctx, access_token_two):
    app, ctx = app_and_ctx

    with app.app_context():
        assert not User.can_use_device(access_token_two, 23)
        assert User.can_use_device(access_token_two, 34)
