from app.app_setup import db
from app.models.models import User, AttrAuthUser, Device, UserDevice


def is_number(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def get_user_by_access_token(token):
    return db.session.query(User).filter(User.access_token == token).first()


def get_aa_user_by_access_token(token):
    return db.session.query(AttrAuthUser).filter(AttrAuthUser.access_token == token).first()


def can_use_device(user_access_token, device_id):
    q = db.session.query(
        db.session.query(User).
        join(UserDevice).
        filter(User.access_token == user_access_token).
        filter(UserDevice.device_id == device_id).
        exists()
    )
    return q.scalar()


def get_device_by_id(device_id):
    return db.session.query(Device).filter(Device.id == device_id).first()
