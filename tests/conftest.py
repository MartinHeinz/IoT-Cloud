import copy
import json
import os
import re
import warnings
import pytest
from click.testing import CliRunner
from sqlalchemy.exc import SADeprecationWarning

from app.app_setup import create_app, db
from app.models.models import UserDevice


@pytest.fixture(scope="module")
def runner():
    return CliRunner(echo_stdin=True)


@pytest.fixture(scope="module")
def client():
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app(os.getenv('TESTING_ENV', "testing"))
    return app.test_client()


@pytest.fixture(scope="module")
def app_and_ctx():
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app(os.getenv('TESTING_ENV', "testing"))
    ctx = app.app_context()
    ctx.push()
    yield app, ctx
    db.drop_all()


@pytest.fixture(scope="module")
def application():
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app(os.getenv('TESTING_ENV', "testing"))
    yield app
    db.drop_all()


# Using SECRET_KEY = "4cb3d264709d34bab510e74bf70541b619a9f95cfcd597d960146a2d479dae27"

@pytest.fixture(scope="session")
def access_token():
    return 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NDM5OTg5NiwiZXhwIjo0NzEwMTU5ODk2fQ.eyJpZCI6MSwidG9rZW4iOiI1YzM2YWI4NDQzOWM0NWEzNzE5NjQ0YzBkOWJkN2IzMTkyOWFmZDlmIn0.PFAF21AJBto5MvHj2aTu-6ni-wWKaqMEUmL0LdPwwm_fzrPH-w7t4772836RD7zjO39vM6bOd29Zr6n2KOrFkQ'  # id_: 1, username: 'MartinHeinz', Provider token: "5c36ab84439c45a3719644c0d9bd7b31929afd9f", Token hash: '$2b$13$XN3Dvx/nQwgPhlAFtk75M.vPxy69SnkZf70t1WNbMAO8ULSR3L7xC'


@pytest.fixture(scope="session")
def access_token_two():
    return 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NDQwNTY3NywiZXhwIjo0NzEwMTY1Njc3fQ.eyJpZCI6MiwidG9rZW4iOiI1YzM2YWI4NDQzOWM1NWEzYzE5NmY0Y3NkOWJkN2IzMTkyOTEyMzlmIn0.qnuO_V75V1WPS4WE-1_fm-Ovl8PxdfCk7m3kwbJazVCELJDm-OEEuGbVPbHDbSpYUzFC6tKGyK5s3v2WgcuJzQ'  # id_: 2, username: 'TestUser', Provider token: "5c36ab84439c55a3c196f4csd9bd7b319291239f", Token hash: '$2b$13$EEqzSBy2inOvO.TyybM3leP2y24ojQLbv7v/e35rLa5HU4j2PO0BC'


@pytest.fixture(scope="session")
def access_token_three():
    return 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NDQwNTYyNCwiZXhwIjo0NzEwMTY1NjI0fQ.eyJpZCI6MywidG9rZW4iOiI1YzM2YWI4NDQzOWM1NWEzYzE5NmY0Y3NkOWJkN2IzZDkyOTFmMzlnIn0.vAqdW4p0-ZTFSjRDRO7ymT4mplXRBh5avlhksjItgvqdH0hHKxa5W80yavu-ygGCOzWEGdbH4jyG_JHEwwtf-A'  # id_: 3, username: 'TestRunner', Provider token: '5c36ab84439c55a3c196f4csd9bd7b3d9291f39g', Token hash: '$2b$13$NALAuz.xCUgoGeZYK5BDK.0WqCKDKBtEWvemr1a4NL4f9rqPxBvkO'


@pytest.fixture(scope="session")
def access_token_four():
    return 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NDQwMDAwMCwiZXhwIjo0NzEwMTYwMDAwfQ.eyJpZCI6NCwidG9rZW4iOiI1YzM2YWI4NDQzOWdkZW4zYzE5NmY0Y3NkOWJkN2IzZDkyOTFmMzlnIn0.y29prR7uJMCnpPQzFHPCL1mFjSfO-x7Wa1aeDRimAn6Qu4t55TTVtaKZcJd_sFh6Gga_HCIC9x4MSP0vyo_qBg'  # id_: 4, username: 'TestRunner2', Provider token: '5c36ab84439gden3c196f4csd9bd7b3d9291f39g', Token hash: '$2b$13$g2aEPfmW9XjDEXwS9wq4l.2m9z.b1B.212jtdn322ohvjge2h0lHK'


@pytest.fixture(scope="session")
def attr_auth_access_token_one():
    return 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NDQwMDAyMywiZXhwIjo0NzEwMTYwMDIzfQ.eyJpZCI6MSwidG9rZW4iOiI1NGFnUHI0ZWRWOVB2eXlCTmtqRmZBKSkifQ.Ur7wcpbN20ATrE1DJFtvrYt3jwoqGbvdL9AJGN99uyzsqup0lywOzJW6HVruDkM3Y4UH0Sm3FA3PaV3y-sF8zQ'  # id_: 1, username: 'Test' Provider token: '54agPr4edV9PvyyBNkjFfA))', Token hash:  '$2b$13$ohFggPHd77552g8HBww1OONSvQTN9.RfwphZYY6eGaIARvzBoOCJy'


@pytest.fixture(scope="session")
def attr_auth_access_token_two():
    return 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NDQwMDA2NiwiZXhwIjo0NzEwMTYwMDY2fQ.eyJpZCI6MiwidG9rZW4iOiI3amFnUHI0ZWRWZGd2eXlCTmtqZGFRKSkifQ.gLDc2mjFGjc8PrZDREi-0GQoRF59nwUIlgcU8POKTkT-X3y7ALr6kDwVOcm-a0JcdetwQBoUgd4sXLWQ3duFzg'  # id_: 2, username: 'TestUser' Provider token: '7jagPr4edVdgvyyBNkjdaQ))', Token hash:  '$2b$13$tBA98L8EtDCiyXrJ4Im0CeJEQ4SeLMD7IG2nH95n86RHmP1d12cVe'


@pytest.fixture(scope="session")
def attr_auth_access_token_three():
    return 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NDQwMDA5NiwiZXhwIjo0NzEwMTYwMDk2fQ.eyJpZCI6MywidG9rZW4iOiI3amFnUHI0ZWRWZGdoY3NCTmtqZDIzKSkifQ.KtvFd6Bwp02-_ltIEoCjHRYTEHdMSVJxwgN5mONspojnVSNqMp6dfFgPl5hq-YsrhJ6Z5JCR4jth9fuuAws-BQ'  # id_: 3, username: 'TestRunner' Provider token: '7jagPr4edVdghcsBNkjd23))', Token hash:  '$2b$13$12bPjvAe8C7hDl4lf7mDPOP9y62o2CfD7OKxfkvn3uS7Le3maFpkq'


@pytest.fixture(scope='function')
def setup_user_device_public_key(request):
    device_id, user_id, pk, db_name = request.param
    warnings.filterwarnings("ignore", category=SADeprecationWarning)
    app = create_app(os.getenv('TESTING_ENV', "testing"))
    with app.app_context():
        _swap_db(app, "testing", db_name)
        _set_user_device_public_key(device_id, user_id, pk)
        _swap_db(app, db_name, "testing")
    yield None
    with app.app_context():
        _swap_db(app, "testing", db_name)
        _set_user_device_public_key(device_id, user_id, None)
        _swap_db(app, db_name, "testing")


@pytest.fixture(scope='function')
def reset_tiny_db(request):
    path = request.param
    if os.path.isfile(path):
        os.remove(path)
    yield None
    os.remove(path)


def _swap_db(app, current, new):
    app.config["SQLALCHEMY_DATABASE_URI"] = re.sub(f"{current}$", new, app.config["SQLALCHEMY_DATABASE_URI"])


def _set_user_device_public_key(device_id, user_id, pk):
    user_device = UserDevice.get_by_ids(device_id, user_id)
    user_device.device_public_session_key = pk
    db.session.add(user_device)
    db.session.commit()


@pytest.fixture(scope='function')
def bi_key():
    return 'f8d25f372070d93ff9756eb928e2082f06ef76ea47638d21f8c6e80b8c370023'


@pytest.fixture(scope='function')
def integrity_data():
    return {
        "device_data": {
            "added": {
                "seed": 1,
                "lower_bound": 0,
                "upper_bound": 0,
                "type": "OPE"
            },
            "num_data": {
                "seed": 2,
                "lower_bound": 0,
                "upper_bound": 0,
                "type": "OPE"
            },
            "data": {
                "seed": 3,
                "lower_bound": 0,
                "upper_bound": 0,
                "type": "ABE"
            },
            "tid": {
                "lower_bound": 0,
                "upper_bound": 0,
                "type": "Fernet"
            },
        }
    }


@pytest.fixture(scope='function')
def aa_public_key():
    return "eJyVVstuGzEM/BXDZx9E7erVXykCwy1S55BDgbQFiiD/Xg05Izs9JQd711yJOzMcUn49Xo9fDq/H8/n78+Xl5Xyev47f/v56fDmeDjP65/L8+9GjX/dxOpR+OtR2OvT5afNTbF7LvKbTYZ/PCmJbxM3q/Mrzrs4VtTLS9ti+NwTm2jrzIrcZojPQ8+1qKccWX55TLG0z2DufWvK7wk0WGas9vE0G1/xReqAAek5NYC3xV98i/XDUO1kCRgIugEx88QTSwXHEIksjtkEvPLCEfDVWW5qRNmI78oFaaNVC0tpJvIkrKHZfogTAvvQoheCRBvCAHagg4RiE67BWDRCG3AAMASwZl3gBfR0U7qj1rrKAekpkloVlC+6wySBlXyAenghkysQ3SAyJoTOSo9zAC1m6k0lClBcsvNcXbUF0F9YiIK6z1yq2RRYt8zLhassrT5/thC6X+8sD1ha1aV3uLkEIYnnRIL5Xooc2UQOsMvWNMSKMnlAidVbAcijmbWfLDa5X5/ve98KPz/KDtk6i0Br4IHE0Y6a8Ts/CRHCiW7epe7xSfWmzCWQ4bFM70RNNnig3dfDbTWmN5EJrKP8fxcfz9Xq+PP98uny47S24EtTO8SOzRvdl6uBfoNpX52ksFU6ywobzIGq880FtmldOAwzQnAh7/xvvdw0Gi+zeQ6vbXdpOf2EYVM6O5SskKFVj0TRO0Az7RmMVmpJFyGsmpADlBsscw9FMeHFlcSLh0DgSp6bpnjXo1sS73+Tnx1B/IoNDvvVpDedpKuIaji/qNGG9ez/VHhpe+80renFXS5Glr2tqNk9RqsSud10J6BhhMINvjKdZFJvUHHcah2EyzV/UIxwb3jM55IxDhnX3ocdzrDRN4xIP8fKm6b+C9R5CpnBCUHk6u6LqNnppnRr1dqy6hSh0YSG9G8DZzzOMJ9wMuY7e4fFQdcI0TVllzWwXNL0OQz+svDh9je32bpglzW7/b1FvR0eTSuuvwhb6xim4Pby9/QMmWbTA"


@pytest.fixture(scope='function')
def user_doc(request):
    bi_key, integrity_data = request.param

    return {
            "id": 1,
            "tid": -1,
            "bi_key": bi_key,
            "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
            "action:name": "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d",
            "device:name": "ae89ebdb00d48b6e2aca3218213888aff3af9915831b9cdde8f82b709fd8802e",
            "device:status": "59cf9693f709a39eb430a05f14604d69e4e3fa5f772f45936bccc97f2d7d417c",
            "device_data:added": "8dabfaf75c380f03e95f55760af02dc84026654cf2019d6da44cc69f600ba8f7",
            "device_data:num_data": "3130d649f90006ef90f5c28fd486a6e748ffc35bad4981799708a411f7acaa60",
            "device_data:data": {
                "private_key": "eJydVstuFDEQ/JXVnhfJ9vjJOYgPCJxQtAooF5QDYgMSivLvuLqrvCPBJTmsdsZj96OqutvPx5vj+8Pz8Xz+9nh/uZzP8+349c/Tw+V4OszV3/ePvx5s9UsJp0Ppp0Mf8z+fDjFu86GdDi3xpc+vdS7EsGEFyyHiaeBpfixzvc2XPJ+bfYGd0Hyl1rkjYGGe7GX+zNbcX+fXAffJz8eIrfM3+KFrw1xr8z/jZIw8XqatjPiCHCBqeB2MsyiOVpWChVd8HyKzYCzeGJhi0/HRHJaYoscUQ/aTcGkHEFFH+NkjJDzJoyv2Ai+Vq+47+meYRGqGdmdqWLCMMilIK5HhPiqP9E3ZiQ1L0fgrZGM4iPSNLSBg7q/2u3uZcrj5blqJr1VMRTybRxxDYMrSiAUV4G3GPgZTt+gMkqUzfC9C2uDZnBZgunhdAsydhK0Hwx0UOUqVfmEG2bbiOJRIMdE84IMCQV8n2/hWK5kYxie8pCC5wx/yNuwlVxMM/JbCo50/hyaK2uwRGbWFBioNIAsLq7r11pbPss84dEUF/TVKHmbtk+8pV1U6rJunY4rL/ltlyHLNXiaOOIvOxAfb9rtKJr5L22vlYh5WNcBVX+XZnB7g11j/5tqL0kQhwcWFqIBjFRkEDtjwvbbP5R9dD62KuixOomxWdbO4E6/JGYF39bXBIIxABI9gu6Rt/aBwAeD6w8YY1MgGmUKBGyfqJ4VoeG2Pa97WQZCyGYTazRUF4wvbrhYsCAPj2rkbmTVI8DYkXFN4G1JwUOJFEt4cF1d5cl8OcaJDa+bde9d/FfPx84fbT68VjSkje/mDgqGZw46W3SGwKOrYmfkM5eu8sVoAmdGwCdRFscx2lkJT1+6JlqwoAyvLdFnlxHtv3Qs4OgWNrHXNHutKSfiyVXhlRNVJZDtZFHlb6uxTwQFnkWQlauwmV40V/8YQOMYNTg4mH/ZSQRKKxUUIiPC+umJzyS/5FSJmLbSyrSZPIavmOgXBDkpbQ2T2f+eRD6Qfr5tIGPjeYoKQ7X4NKORgsC7XNUOdsBPRuu4B3mCTG2q6bKwJ1tRhvFS6FBT77uJhvaZrIrEvZFUiCucNjVRZds1ydZK6bhdpP3ivQ7+zReWuScEiRZyZlqy+U1Sh6/ZXpY6qfNJuslSNx6HKKJSx1/9bal95Nt1mkFFnKD5rKUYTJGt5sHuuorIi15wDOyZ6dgDrkzYVpMUmavO+0+TrFc+EsS4pTmS5ivYWoR8vTz/fR2RkDyB3PTsGdy9/AbtMQWU=",
                "attr_list": [
                    "1-23",
                    "1-GUEST",
                    "1"
                ]
            },
            "device_data:tid": "9692e6525c19e6fa37978626606534015cd120816a28b501bebec142d86002b2",
            "scene:name": "cc3e027214ce8934640654a5282305bf31fd2f77e87378d137f9c2c0e6702883",
            "scene:description": "56c11e781fa7f93d114ac323f3c40a3261909747b6e05e371004f10afb6a30da",
            "integrity": {integrity_data}
        }


@pytest.fixture(scope='function')
def col_keys():
    data = {
        "device_id": "23",
        "bi_key": "7e4f38411a597dabef47fd98d9a6346dc2badecc6acd3a6d862ad6b2cd9863ed",
        "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
        "action:name": "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d",
        "device_data:added": "8dabfaf75c380f03e95f55760af02dc84026654cf2019d6da44cc69f600ba8f7",
        "device_data:num_data": "3130d649f90006ef90f5c28fd486a6e748ffc35bad4981799708a411f7acaa60",
        "device_data:data": {
            "private_key": "eJydVstuFDEQ/JXVnhfJ9vjJOYgPCJxQtAooF5QDYgMSivLvuLqrvCPBJTmsdsZj96OqutvPx5vj+8Pz8Xz+9nh/uZzP8+349c/Tw+V4OszV3/ePvx5s9UsJp0Ppp0Mf8z+fDjFu86GdDi3xpc+vdS7EsGEFyyHiaeBpfixzvc2XPJ+bfYGd0Hyl1rkjYGGe7GX+zNbcX+fXAffJz8eIrfM3+KFrw1xr8z/jZIw8XqatjPiCHCBqeB2MsyiOVpWChVd8HyKzYCzeGJhi0/HRHJaYoscUQ/aTcGkHEFFH+NkjJDzJoyv2Ai+Vq+47+meYRGqGdmdqWLCMMilIK5HhPiqP9E3ZiQ1L0fgrZGM4iPSNLSBg7q/2u3uZcrj5blqJr1VMRTybRxxDYMrSiAUV4G3GPgZTt+gMkqUzfC9C2uDZnBZgunhdAsydhK0Hwx0UOUqVfmEG2bbiOJRIMdE84IMCQV8n2/hWK5kYxie8pCC5wx/yNuwlVxMM/JbCo50/hyaK2uwRGbWFBioNIAsLq7r11pbPss84dEUF/TVKHmbtk+8pV1U6rJunY4rL/ltlyHLNXiaOOIvOxAfb9rtKJr5L22vlYh5WNcBVX+XZnB7g11j/5tqL0kQhwcWFqIBjFRkEDtjwvbbP5R9dD62KuixOomxWdbO4E6/JGYF39bXBIIxABI9gu6Rt/aBwAeD6w8YY1MgGmUKBGyfqJ4VoeG2Pa97WQZCyGYTazRUF4wvbrhYsCAPj2rkbmTVI8DYkXFN4G1JwUOJFEt4cF1d5cl8OcaJDa+bde9d/FfPx84fbT68VjSkje/mDgqGZw46W3SGwKOrYmfkM5eu8sVoAmdGwCdRFscx2lkJT1+6JlqwoAyvLdFnlxHtv3Qs4OgWNrHXNHutKSfiyVXhlRNVJZDtZFHlb6uxTwQFnkWQlauwmV40V/8YQOMYNTg4mH/ZSQRKKxUUIiPC+umJzyS/5FSJmLbSyrSZPIavmOgXBDkpbQ2T2f+eRD6Qfr5tIGPjeYoKQ7X4NKORgsC7XNUOdsBPRuu4B3mCTG2q6bKwJ1tRhvFS6FBT77uJhvaZrIrEvZFUiCucNjVRZds1ydZK6bhdpP3ivQ7+zReWuScEiRZyZlqy+U1Sh6/ZXpY6qfNJuslSNx6HKKJSx1/9bal95Nt1mkFFnKD5rKUYTJGt5sHuuorIi15wDOyZ6dgDrkzYVpMUmavO+0+TrFc+EsS4pTmS5ivYWoR8vTz/fR2RkDyB3PTsGdy9/AbtMQWU=",
            "attr_list": ["1-23", "1-GUEST", "1"]
        },
        "device_data:tid": "9692e6525c19e6fa37978626606534015cd120816a28b501bebec142d86002b2",
        "device:name": "ae89ebdb00d48b6e2aca3218213888aff3af9915831b9cdde8f82b709fd8802e",
    }
    return data


@pytest.fixture(scope='function')
def device_col_keys():
    data = {
        "id": 1,
        "tid": -1,
        "bi_key": "7e4f38411a597dabef47fd98d9a6346dc2badecc6acd3a6d862ad6b2cd9863ed",
        "shared_key": "aefe715635c3f35f7c58da3eb410453712aaf1f8fd635571aa5180236bb21acc",
        "action:name": "a70c6a23f6b0ef9163040f4cc02819c22d7e35de6469672d250519077b36fe4d",
        "device_data:added": "8dabfaf75c380f03e95f55760af02dc84026654cf2019d6da44cc69f600ba8f7",
        "device_data:num_data": "3130d649f90006ef90f5c28fd486a6e748ffc35bad4981799708a411f7acaa60",
        "device_data:data": {
            "public_key": "eJyVVstuGzEM/BXDZx9E7erVXykCwy1S55BDgbQFiiD/Xg05Izs9JQd711yJOzMcUn49Xo9fDq/H8/n78+Xl5Xyev47f/v56fDmeDjP65/L8+9GjX/dxOpR+OtR2OvT5afNTbF7LvKbTYZ/PCmJbxM3q/Mrzrs4VtTLS9ti+NwTm2jrzIrcZojPQ8+1qKccWX55TLG0z2DufWvK7wk0WGas9vE0G1/xReqAAek5NYC3xV98i/XDUO1kCRgIugEx88QTSwXHEIksjtkEvPLCEfDVWW5qRNmI78oFaaNVC0tpJvIkrKHZfogTAvvQoheCRBvCAHagg4RiE67BWDRCG3AAMASwZl3gBfR0U7qj1rrKAekpkloVlC+6wySBlXyAenghkysQ3SAyJoTOSo9zAC1m6k0lClBcsvNcXbUF0F9YiIK6z1yq2RRYt8zLhassrT5/thC6X+8sD1ha1aV3uLkEIYnnRIL5Xooc2UQOsMvWNMSKMnlAidVbAcijmbWfLDa5X5/ve98KPz/KDtk6i0Br4IHE0Y6a8Ts/CRHCiW7epe7xSfWmzCWQ4bFM70RNNnig3dfDbTWmN5EJrKP8fxcfz9Xq+PP98uny47S24EtTO8SOzRvdl6uBfoNpX52ksFU6ywobzIGq880FtmldOAwzQnAh7/xvvdw0Gi+zeQ6vbXdpOf2EYVM6O5SskKFVj0TRO0Az7RmMVmpJFyGsmpADlBsscw9FMeHFlcSLh0DgSp6bpnjXo1sS73+Tnx1B/IoNDvvVpDedpKuIaji/qNGG9ez/VHhpe+80renFXS5Glr2tqNk9RqsSud10J6BhhMINvjKdZFJvUHHcah2EyzV/UIxwb3jM55IxDhnX3ocdzrDRN4xIP8fKm6b+C9R5CpnBCUHk6u6LqNnppnRr1dqy6hSh0YSG9G8DZzzOMJ9wMuY7e4fFQdcI0TVllzWwXNL0OQz+svDh9je32bpglzW7/b1FvR0eTSuuvwhb6xim4Pby9/QMmWbTA",
            "policy": "(1-23 OR 1-GUEST OR 1)"
        },
        "device_data:tid": "9692e6525c19e6fa37978626606534015cd120816a28b501bebec142d86002b2",
        "device:name": "ae89ebdb00d48b6e2aca3218213888aff3af9915831b9cdde8f82b709fd8802e",
        "scene_key": "999d1785bab02131da22f440016c9568a059c73266dbac8964f27fbd0af6bee8",
    }
    return data


def assert_got_error_from_post(client, url, data, error_code, error_string="", follow_redirects=True):
    access_token_header = {"Authorization": data["access_token"]}
    data_copy = copy.deepcopy(data)
    data_copy.pop("access_token")
    response = client.post(url, headers=access_token_header, data=data_copy, follow_redirects=follow_redirects)
    assert response.status_code == error_code
    json_data = json.loads(response.data.decode("utf-8"))
    if error_string != "":
        assert json_data["error"] == error_string


def assert_got_data_from_post(client, url, data_in, follow_redirects=True, **data_out):
    access_token_header = {"Authorization": data_in["access_token"]}
    data_copy = copy.deepcopy(data_in)
    data_copy.pop("access_token")
    response = client.post(url, headers=access_token_header, data=data_copy, follow_redirects=follow_redirects)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    for k, v in data_out.items():
        assert json_data[k] == v


def get_data_from_post(client, url, data, follow_redirects=True):
    access_token_header = {"Authorization": data["access_token"]}
    data_copy = copy.deepcopy(data)
    data_copy.pop("access_token")
    response = client.post(url, headers=access_token_header, data=data_copy, follow_redirects=follow_redirects)
    json_data = json.loads(response.data.decode("utf-8"))
    return response.status_code, json_data


def assert_got_error_from_get(client, url, data, error_code, error_string="", follow_redirects=True):
    access_token_header = {"Authorization": data["access_token"]}
    response = client.get(url, headers=access_token_header, query_string=data, follow_redirects=follow_redirects)
    assert response.status_code == error_code
    json_data = json.loads(response.data.decode("utf-8"))
    if error_string != "":
        assert json_data["error"] == error_string


def assert_got_data_from_get(client, url, data_in, follow_redirects=True, **data_out):
    access_token_header = {"Authorization": data_in["access_token"]}
    response = client.get(url, headers=access_token_header, query_string=data_in, follow_redirects=follow_redirects)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    for k, v in data_out.items():
        assert json_data[k] == v


def get_data_from_get(client, url, data, follow_redirects=True):
    access_token_header = {"Authorization": data["access_token"]}
    response = client.get(url, headers=access_token_header, query_string=data, follow_redirects=follow_redirects)
    json_data = json.loads(response.data.decode("utf-8"))
    return response.status_code, json_data
