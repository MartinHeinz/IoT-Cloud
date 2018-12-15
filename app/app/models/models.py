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
    devices = relationship(
        "Device",
        secondary=user_device_table,
        back_populates="users")


class DeviceType(db.Model):  # TODO associate type with user so someone can modify/delete it
    __tablename__ = 'device_type'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    type_id = db.Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid4)
    description = db.Column(db.String(200), unique=False, nullable=True)
    devices = relationship("Device", cascade="all, delete-orphan", back_populates="device_type")


class Device(db.Model):
    __tablename__ = 'device'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.Boolean, default=False)
    device_type = relationship("DeviceType", back_populates="devices")
    device_type_id = db.Column(db.Integer, db.ForeignKey('device_type.id'))
    users = relationship(
        "User",
        secondary=user_device_table,
        back_populates="devices")
    data = relationship("DeviceData", back_populates="device")
    actions = relationship("Action", back_populates="device")
    scenes = relationship(
        "Scene",
        secondary=scene_device_table,
        back_populates="devices")

    name = db.Column(db.String(200), unique=False, nullable=True)
    name_bi = db.Column(db.String(200), unique=False, nullable=True)  # Blind index for .name

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class DeviceData(db.Model):
    __tablename__ = 'device_data'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    added = db.Column(db.DateTime(timezone=True), server_default=func.now())
    data = db.Column(db.LargeBinary)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    device = relationship("Device", back_populates="data")


class Action(db.Model):
    __tablename__ = 'action'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=False, nullable=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    device = relationship("Device", back_populates="actions")


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
