from datetime import date, datetime

from paho.mqtt.client import MQTTMessage
from sqlalchemy import and_

from app.app_setup import db
from app.models.models import UserDevice
from app.mqtt.utils import Payload


def test_payload_init():
    p = Payload(device_id=111111,
                device_data="test_data",
                added=date(2001, 3, 28),
                num_data=840125,
                data=b'\\001',
                correctness_hash='$2b$12$5s/6DQkc3Tkq.9dXQ9fK/usP1usuyQh1rpsh5dBCQee8UXdVI7.6e')

    assert p.device_id == 111111
    assert p.device_data == "test_data"
    assert p.added == date(2001, 3, 28)
    assert p.num_data == 840125
    assert p.correctness_hash == '$2b$12$5s/6DQkc3Tkq.9dXQ9fK/usP1usuyQh1rpsh5dBCQee8UXdVI7.6e'
    assert p.data == b'\\001'


def test_payload_bytes():
    p = Payload(device_id=111111, device_data='test_data')
    assert bytes(p) == b"{'device_id': '111111', 'device_data': 'test_data'}"

    p = Payload(added=date(2001, 3, 28),
                data=b'\\001')
    assert bytes(p) == b"{'added': '2001-03-28', 'data': '\\001'}"


def test_payload_string():
    p = Payload(device_id=111111, device_data='test_data')
    assert str(p) == '{\n    "device_id": "111111",\n    "device_data": "test_data"\n}'

    p = Payload(added=date(2001, 3, 28),
                data=b'\\001')
    assert str(p) == '{\n    "added": "2001-03-28",\n    "data": "\\\\001"\n}'


def test_mqtt_handle_on_message_receive_pk(app_and_ctx):
    pk = b'-----BEGIN PUBLIC KEY-----\\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2rD6Bhju8WSEFogdBxZt/N+n7ziUPi5C\\nQU1gSQQDNm57fdDuYNDOR7Wwb1fq5tSl2TC1D6WRTIt1gzzCsApGpZ3PIs7Wdbil\\neJL/ETGa2Sqwav7JDH4r0V30sF4NqDok\\n-----END PUBLIC KEY-----\\n'
    user_id = 1
    device_id = 23
    msg = MQTTMessage(topic=b"%a/server" % device_id)
    msg.payload = b"{'user_id': %a, " \
                  b"'device_public_key': '%b'}" % (user_id, pk)
    from app.mqtt.mqtt import handle_on_message
    app, ctx = app_and_ctx
    with app.app_context():
        user_device = db.session.query(UserDevice)\
            .filter(and_(UserDevice.device_id == device_id,
                         UserDevice.user_id == user_id)).first()
        assert user_device.device_public_session_key is None
        assert user_device.added is None

        handle_on_message(None, None, msg, app, db)
        user_device = db.session.query(UserDevice)\
            .filter(and_(UserDevice.device_id == device_id,
                         UserDevice.user_id == user_id)).first()

        assert user_device.device_public_session_key == pk.decode().replace("\\n", "\n")
        assert isinstance(user_device.added, datetime)


def test_mqtt_handle_on_message_receive_pk_invalid_device_id(app_and_ctx, capsys):
    pk = b'-----BEGIN PUBLIC KEY-----\\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2rD6Bhju8WSEFogdBxZt/N+n7ziUPi5C\\nQU1gSQQDNm57fdDuYNDOR7Wwb1fq5tSl2TC1D6WRTIt1gzzCsApGpZ3PIs7Wdbil\\neJL/ETGa2Sqwav7JDH4r0V30sF4NqDok\\n-----END PUBLIC KEY-----\\n'
    user_id = 1
    device_id = "invalid"
    msg = MQTTMessage(topic=b"%b/server" % device_id.encode())
    msg.payload = b"{'user_id': %a, " \
                  b"'device_public_key': '%b'}" % (user_id, pk)
    from app.mqtt.mqtt import handle_on_message
    app, ctx = app_and_ctx
    with app.app_context():
        handle_on_message(None, None, msg, app, db)
        captured = capsys.readouterr()
        assert f"Invalid device ID: {device_id}" in captured.out


def test_mqtt_handle_on_message_receive_pk_user_doesnt_have_this_device(app_and_ctx, capsys):
    pk = b'-----BEGIN PUBLIC KEY-----\\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2rD6Bhju8WSEFogdBxZt/N+n7ziUPi5C\\nQU1gSQQDNm57fdDuYNDOR7Wwb1fq5tSl2TC1D6WRTIt1gzzCsApGpZ3PIs7Wdbil\\neJL/ETGa2Sqwav7JDH4r0V30sF4NqDok\\n-----END PUBLIC KEY-----\\n'
    user_id = 1
    device_id = 34
    msg = MQTTMessage(topic=b"%a/server" % device_id)
    msg.payload = b"{'user_id': %a, " \
                  b"'device_public_key': '%b'}" % (user_id, pk)
    from app.mqtt.mqtt import handle_on_message
    app, ctx = app_and_ctx
    with app.app_context():
        handle_on_message(None, None, msg, app, db)
        captured = capsys.readouterr()
        assert f"This User can't access device {device_id}" in captured.out
