import json

from charm.schemes.abenc.ac17 import AC17CPABE
from charm.toolbox.pairinggroup import PairingGroup, GT

from app.app_setup import db
from app.attribute_authority.endpoints import INCORRECT_RECEIVER_ID_ERROR_MSG, INVALID_ATTR_LIST_ERROR_MSG
from app.attribute_authority.utils import create_pairing_group, create_cp_abe, serialize_key, deserialize_key, already_has_key_from_owner, create_attributes, \
    replace_existing_key, parse_attr_list
from app.auth.utils import INVALID_ACCESS_TOKEN_ERROR_MSG
from app.models.models import AttrAuthUser


def test_charm_crypto():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')

    # AC17 CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # run the set up
    (pk, msk) = cpabe.setup()  # Public Key and Master SECRET Key

    # generate a key
    attr_list = ['TODAY']
    key = cpabe.keygen(pk, msk, attr_list)

    # choose a random message
    msg = pairing_group.random(GT)  # This won't be needed

    # generate a ciphertext
    policy_str = '(TODAY)'
    ctxt = cpabe.encrypt(pk, msg, policy_str)

    policy_str = '(TOMORROW)'  # Re-encrypted data with new policy
    ctxt2 = cpabe.encrypt(pk, msg, policy_str)

    # decryption
    rec_msg = cpabe.decrypt(pk, ctxt, key)
    rec_msg2 = cpabe.decrypt(pk, ctxt2, key)
    assert rec_msg == msg and rec_msg2 != msg, "Failed."  # "First successfully decrypted, second not."


def test_serialize_and_deserialize_pk():
    pairing_group = create_pairing_group()
    cp_abe = create_cp_abe()

    public_key, master_key = cp_abe.setup()

    assert public_key == deserialize_key(serialize_key(public_key, pairing_group), pairing_group)


def test_require_attr_auth_access_token_missing(client):
    data = {"access_token": "missing"}
    response = client.post('/attr_auth/setup', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == INVALID_ACCESS_TOKEN_ERROR_MSG


def test_key_setup(client, app_and_ctx, attr_auth_access_token):
    data = {"access_token": attr_auth_access_token}
    response = client.post('/attr_auth/setup', query_string=data, follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data.decode("utf-8"))
    serialized_public_key_response = json_data["public_key"]

    app, ctx = app_and_ctx
    with app.app_context():
        serialized_public_key_from_db = db.session.query(AttrAuthUser)\
            .filter(AttrAuthUser.access_token == data["access_token"])\
            .first()\
            .public_key.data.decode("utf-8")
        assert serialized_public_key_response == serialized_public_key_from_db


def test_already_has_key_from_owner(app_and_ctx):
    app, ctx = app_and_ctx
    with app.app_context():
        owner = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == "54agPr4edV9PvyyBNkjFfA))") \
            .first()
        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == "7jagPr4edVdgvyyBNkjdaQ))") \
            .first()

        assert already_has_key_from_owner(receiver, owner)


def test_doesnt_have_key_from_owner(app_and_ctx):
    app, ctx = app_and_ctx
    with app.app_context():
        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == "7jagPr4edVdgvyyBNkjdaQ))") \
            .first()

        owner = AttrAuthUser()

        assert not already_has_key_from_owner(receiver, owner)


def test_create_attributes():
    attr_list = ["TODAY", "TOMORROW"]
    attrs = create_attributes(attr_list)
    assert attrs[0].value == "TODAY"
    assert attrs[1].value == "TOMORROW"
    assert len(attrs) == 2


def test_replace_existing_key(app_and_ctx):
    app, ctx = app_and_ctx
    attr_list = ["TODAY", "TOMORROW"]
    dummy_serialized_key = b'key'
    with app.app_context():
        owner = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == "54agPr4edV9PvyyBNkjFfA))") \
            .first()
        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == "7jagPr4edVdgvyyBNkjdaQ))") \
            .first()

        replace_existing_key(receiver, dummy_serialized_key, owner, attr_list)
        modified_key = receiver.private_keys[0]
        assert modified_key.data == dummy_serialized_key
        assert modified_key.attributes[0].value == "TODAY"


def test_keygen_invalid_receiver(client, master_key_user_one, attr_auth_access_token):
    data = {
        "access_token": attr_auth_access_token,
        "master_key": master_key_user_one,
        "attr_list": "TODAY_GUEST, ANOTHER",
        "receiver_id": "15"
    }
    response = client.post('/attr_auth/keygen', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == INCORRECT_RECEIVER_ID_ERROR_MSG
    data = {
        "access_token": attr_auth_access_token,
        "master_key": master_key_user_one,
        "attr_list": "TODAY_GUEST, ANOTHER",
        "receiver_id": "eth"
    }
    response = client.post('/attr_auth/keygen', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == INCORRECT_RECEIVER_ID_ERROR_MSG


def test_keygen_invalid_attr_list(client, master_key_user_one, attr_auth_access_token):
    data = {
        "access_token": attr_auth_access_token,
        "master_key": master_key_user_one,
        "attr_list": "TODAY_GUEST, ANOTHER",
        "receiver_id": "2"
    }
    response = client.post('/attr_auth/keygen', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == INVALID_ATTR_LIST_ERROR_MSG


def test_parse_attr_list():
    attr_list = 'QH QD\t JC KD 4   JS'
    empty_attr_list = ''
    invalid_attr_list = 'Q-H QD JC K_D JS'
    assert parse_attr_list(attr_list) == ['QH', 'QD', 'JC', 'KD', '4', 'JS']
    assert len(parse_attr_list(empty_attr_list)) == 0
    assert len(parse_attr_list(invalid_attr_list)) == 0
