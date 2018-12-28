from datetime import date

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


def test_payload_bytes():
    p = Payload(device_id=111111, device_data='test_data')
    assert str(p) == '{\n    "device_id": "111111",\n    "device_data": "test_data"\n}'

    p = Payload(added=date(2001, 3, 28),
                data=b'\\001')
    assert str(p) == '{\n    "added": "2001-03-28",\n    "data": "\\\\001"\n}'
