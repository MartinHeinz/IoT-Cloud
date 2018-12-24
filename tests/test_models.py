from app.models.models import DeviceType

from .conftest import db
from tests.test_utils.utils import is_valid_uuid


def test_device_type_uuid(app_and_ctx):
    app, ctx = app_and_ctx

    with app.app_context():
        dt = DeviceType()
        db.session.add(dt)
        db.session.commit()
        assert is_valid_uuid(str(dt.type_id))
