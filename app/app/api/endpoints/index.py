from app.app_setup import db
from app.models.user import User
from . import home


@home.route('/')
def hello():
    return str(db.session.query(User).count())
