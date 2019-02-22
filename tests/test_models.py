from app.models.models import DeviceType, User, Device, MQTTUser, Scene, UserDevice
from app.utils import is_valid_uuid
from client.crypto_utils import correctness_hash

from .conftest import db


def test_can_use_device(app_and_ctx, access_token, access_token_two):
    app, ctx = app_and_ctx
    device_id = 23

    with app.app_context():
        assert not User.can_use_device(access_token, "non a number")
        assert not User.can_use_device(access_token, 45)
        assert User.can_use_device(access_token, device_id)

        assert not User.can_use_device(access_token_two, device_id)
        ud = UserDevice()
        dv = Device.get_by_id(device_id)
        user = User.get_by_access_token(access_token_two)
        ud.device = dv
        with db.session.no_autoflush:
            ud.user = user
        db.session.add(ud)
        db.session.commit()
        assert User.can_use_device(access_token_two, device_id)

        ud = UserDevice.get_by_ids(device_id, user.id)  # Clean-up
        dv.users.remove(ud)
        db.session.add(dv)
        assert not User.can_use_device(access_token_two, device_id)


def test_device_type_uuid(app_and_ctx):
    app, ctx = app_and_ctx

    with app.app_context():
        dt = DeviceType(description=b"nothing", correctness_hash=correctness_hash("nothing"))
        db.session.add(dt)
        db.session.commit()
        assert is_valid_uuid(str(dt.type_id))


def test_get_action_by_bi(app_and_ctx):
    app, ctx = app_and_ctx

    with app.app_context():
        ac = Device.get_action_by_bi(23, '86a638eab77f45b9e0e2fb384471e517664df67cec75c33d724efa8649be357e')
        assert ac.correctness_hash == '$2b$12$jOfamxBlpNv4BM0Ro3t9uOjLOxkA28J8/82vHAG7m9H.roDBlntPi'


def test_is_device():
    user = MQTTUser()
    assert not user.is_device

    user.device = Device()
    assert user.is_device


def test_is_registered_with_broker():
    user = User(mqtt_creds=MQTTUser())
    assert user.is_registered_with_broker

    user = User()
    assert not user.is_registered_with_broker


def test_scene_owner(app_and_ctx, access_token_two):
    app, ctx = app_and_ctx

    with app.app_context():
        sc = db.session.query(Scene).filter(Scene.name_bi == '0b0a367318926df75879294f1520905ba72d8f1bebe64865645a7e108bfaf3e4').first()
        assert sc.owner.access_token == access_token_two

    sc_no_owner = Scene()
    assert sc_no_owner.owner is None
