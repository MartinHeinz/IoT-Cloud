from app.app_setup import db
from app.utils import is_number


class MixinGetById:
    id = db.Column(db.Integer, primary_key=True)

    @classmethod
    def get_by_id(cls, id_):
        if is_number(id_):
            return db.session.query(cls).filter(cls.id == id_).first()
        return None


class MixinGetByUsername:
    api_username = db.Column(db.String(200), unique=True, nullable=True)

    @classmethod
    def get_by_user_name(cls, user_name):
        return db.session.query(cls).filter(cls.api_username == user_name).first()


class MixinGetByAccessToken:
    access_token = db.Column(db.String(200), unique=True, nullable=False)

    @classmethod
    def get_by_access_token(cls, token):
        return db.session.query(cls).filter(cls.access_token == token).first()


class MixinAsDict:
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
