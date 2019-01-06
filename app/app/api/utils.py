from app.app_setup import db
from app.models.models import User, AttrAuthUser


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
