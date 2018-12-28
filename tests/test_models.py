from app.models.models import DeviceType
from app.utils import is_valid_uuid
from client.crypto_utils import correctness_hash

from .conftest import db


def test_device_type_uuid(app_and_ctx):
    app, ctx = app_and_ctx

    with app.app_context():
        dt = DeviceType(description="nothing", correctness_hash=correctness_hash("nothing"))
        db.session.add(dt)
        db.session.commit()
        assert is_valid_uuid(str(dt.type_id))
