from uuid import uuid4
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.app_setup import db

user_device_table = db.Table('user_device',
                             db.Column("user_id", db.Integer, db.ForeignKey('user.id')),
                             db.Column('device_id', db.Integer, db.ForeignKey('device.id')),
                             extend_existing=True
                             )

scene_device_table = db.Table('scene_device',
                              db.Column("scene_id", db.Integer, db.ForeignKey('scene.id')),
                              db.Column('device_id', db.Integer, db.ForeignKey('device.id')),
                              extend_existing=True
                              )


class User(db.Model):
    __tablename__ = 'user'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=False, nullable=True)
    email = db.Column(db.String(200), unique=False, nullable=True)
    access_token = db.Column(db.String(200), unique=True, nullable=False)  # TODO Give the token expiration date/time and force user to generate new token through `/login` endpoint
    access_token_update = db.Column(db.DateTime, nullable=False)
    device_types = relationship("DeviceType", back_populates="owner")

    devices = relationship(
        "Device",
        secondary=user_device_table,
        back_populates="users")
    owned_devices = relationship("Device", back_populates="owner")


class DeviceType(db.Model):
    __tablename__ = 'device_type'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    type_id = db.Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid4)
    description = db.Column(db.String(200), unique=False, nullable=True)
    devices = relationship("Device", cascade="all, delete-orphan", back_populates="device_type")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owner = relationship("User", back_populates="device_types")

    correctness_hash = db.Column(db.String(200), nullable=False)  # correctness_hash("description")


class Device(db.Model):
    __tablename__ = 'device'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.Boolean, default=False)
    device_type = relationship("DeviceType", back_populates="devices")
    device_type_id = db.Column(db.Integer, db.ForeignKey('device_type.id'))
    users = relationship(  # TODO Maybe remove this?
        "User",
        secondary=user_device_table,
        back_populates="devices")
    data = relationship("DeviceData", back_populates="device")
    actions = relationship("Action", back_populates="device")
    scenes = relationship(
        "Scene",
        secondary=scene_device_table,
        back_populates="devices")
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owner = relationship("User", back_populates="owned_devices")

    name = db.Column(db.String(200), unique=False, nullable=True)
    name_bi = db.Column(db.String(200), unique=False, nullable=True)  # Blind index for .name

    correctness_hash = db.Column(db.String(200), nullable=False)  # correctness_hash("name")

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class DeviceData(db.Model):
    __tablename__ = 'device_data'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    added = db.Column(db.DateTime(timezone=True), server_default=func.now())
    num_data = db.Column(db.Integer)
    data = db.Column(db.LargeBinary)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    device = relationship("Device", back_populates="data")

    correctness_hash = db.Column(db.String(200), nullable=False)  # correctness_hash(str(date(2018, 12, 11)), b'\\001'.decode("utf-8"), str(214357163))

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class Action(db.Model):
    __tablename__ = 'action'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=False, nullable=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    device = relationship("Device", back_populates="actions")

    correctness_hash = db.Column(db.String(200), nullable=False)  # correctness_hash("name")


class Scene(db.Model):
    __tablename__ = 'scene'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=False, nullable=True)
    description = db.Column(db.String(200), unique=False, nullable=True)
    devices = relationship(
        "Device",
        secondary=scene_device_table,
        back_populates="scenes")

    correctness_hash = db.Column(db.String(200), nullable=False)  # correctness_hash("name", "description")


class AttrAuthUser(db.Model):
    __table_args__ = {'extend_existing': True}
    __bind_key__ = 'attr_auth'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=False, nullable=True)
    access_token = db.Column(db.String(200), unique=True, nullable=False)  # TODO Give the token expiration date/time and force user to generate new token through `/login` endpoint
    access_token_update = db.Column(db.DateTime, nullable=False)
    public_key = relationship("PublicKey", back_populates="attr_auth_user", uselist=False)

    private_keys = relationship("PrivateKey", backref="user", foreign_keys=lambda: PrivateKey.user_id)


class PrivateKey(db.Model):
    __table_args__ = {'extend_existing': True}
    __bind_key__ = 'attr_auth'

    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)
    key_update = db.Column(db.DateTime(timezone=True), server_default=func.now())
    attributes = relationship("Attribute", backref="private_key")

    user_id = db.Column(db.Integer, db.ForeignKey('attr_auth_user.id'))

    challenger_id = db.Column(db.Integer, db.ForeignKey('attr_auth_user.id'))
    challenger = relationship("AttrAuthUser", uselist=False, foreign_keys=[challenger_id])


class PublicKey(db.Model):
    __table_args__ = {'extend_existing': True}
    __bind_key__ = 'attr_auth'

    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)
    key_update = db.Column(db.DateTime(timezone=True), server_default=func.now())
    attr_auth_user_id = db.Column(db.Integer, db.ForeignKey('attr_auth_user.id'))
    attr_auth_user = relationship("AttrAuthUser", back_populates="public_key")


class Attribute(db.Model):
    __table_args__ = {'extend_existing': True}
    __bind_key__ = 'attr_auth'

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(200), unique=False, nullable=True)

    private_key_id = db.Column(db.Integer, db.ForeignKey('private_key.id'))
