import json

import pytest
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
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

    cpabe = CPabe_BSW07(pairing_group)
    hyb_abe = HybridABEnc(cpabe, pairing_group)
    # run the set up
    (pk, msk) = hyb_abe.setup()  # Public Key and Master SECRET Key

    # generate a key
    attr_list = ['TODAY']
    key = hyb_abe.keygen(pk, msk, attr_list)

    serialized_pk = serialize_key(pk, pairing_group)
    pk = deserialize_key(serialized_pk, pairing_group)

    serialized_key = serialize_key(key, pairing_group)
    key = deserialize_key(serialized_key, pairing_group)

    # choose a random message
    msg = "Hello World"

    # generate a ciphertext
    policy_str = '(TODAY)'
    ctxt = hyb_abe.encrypt(pk, msg, policy_str)

    policy_str = '(TOMORROW)'  # Re-encrypted data with new policy
    ctxt2 = hyb_abe.encrypt(pk, msg, policy_str)

    # decryption
    rec_msg = hyb_abe.decrypt(pk, key, ctxt).decode("utf-8")
    with pytest.raises(Exception):
        hyb_abe.decrypt(pk, key, ctxt2)
    assert rec_msg == msg, "Failed."  # "First successfully decrypted, second not."


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


def test_already_has_key_from_owner(app_and_ctx, attr_auth_access_token_two):
    app, ctx = app_and_ctx
    with app.app_context():
        owner = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == "54agPr4edV9PvyyBNkjFfA))") \
            .first()
        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == attr_auth_access_token_two) \
            .first()

        assert already_has_key_from_owner(receiver, owner)


def test_doesnt_have_key_from_owner(app_and_ctx, attr_auth_access_token_two):
    app, ctx = app_and_ctx
    with app.app_context():
        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == attr_auth_access_token_two) \
            .first()

        owner = AttrAuthUser()

        assert not already_has_key_from_owner(receiver, owner)


def test_create_attributes():
    attr_list = ["TODAY", "TOMORROW"]
    attrs = create_attributes(attr_list)
    assert attrs[0].value == "TODAY"
    assert attrs[1].value == "TOMORROW"
    assert len(attrs) == 2


def test_keygen_invalid_receiver(client, master_key_user_one, attr_auth_access_token_one):
    data = {
        "access_token": attr_auth_access_token_one,
        "master_key": master_key_user_one,
        "attr_list": "TODAY_GUEST, ANOTHER",
        "receiver_id": "15"
    }
    response = client.post('/attr_auth/keygen', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == INCORRECT_RECEIVER_ID_ERROR_MSG
    data = {
        "access_token": attr_auth_access_token_one,
        "master_key": master_key_user_one,
        "attr_list": "TODAY_GUEST, ANOTHER",
        "receiver_id": "eth"
    }
    response = client.post('/attr_auth/keygen', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == INCORRECT_RECEIVER_ID_ERROR_MSG


def test_keygen_invalid_attr_list(client, master_key_user_one, attr_auth_access_token_one):
    data = {
        "access_token": attr_auth_access_token_one,
        "master_key": master_key_user_one,
        "attr_list": "TODAY_GUEST, ANOTHER",
        "receiver_id": "2"
    }
    response = client.post('/attr_auth/keygen', query_string=data, follow_redirects=True)
    assert response.status_code == 400
    json_data = json.loads(response.data.decode("utf-8"))
    assert (json_data["error"]) == INVALID_ATTR_LIST_ERROR_MSG


def test_keygen_already_has_key_from_owner(client, app_and_ctx, master_key_user_one, attr_auth_access_token_one, attr_auth_access_token_two):
    data = {
        "access_token": attr_auth_access_token_one,
        "master_key": master_key_user_one,
        "attr_list": "TODAY GUEST",
        "receiver_id": "2"
    }
    app, ctx = app_and_ctx
    with app.app_context():
        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == attr_auth_access_token_two) \
            .first()  # TestUser access_token
        old_private_key = next(key for key in receiver.private_keys if key.challenger_id == 1)
        old_private_key_data = old_private_key.data
        old_private_key_key_update = old_private_key.key_update

        response = client.post('/attr_auth/keygen', query_string=data, follow_redirects=True)
        assert response.status_code == 200

        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == attr_auth_access_token_two) \
            .first()  # TestUser access_token
        new_private_key = next(key for key in receiver.private_keys if key.challenger_id == 1)

        assert old_private_key_data != new_private_key.data
        assert old_private_key_key_update < new_private_key.key_update

        # Try to encrypt and decrypt
        pairing_group = create_pairing_group()
        cp_abe = create_cp_abe()
        plaintext = "Hello World"
        data_owner = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == attr_auth_access_token_one) \
            .first()
        policy_str = '(TODAY)'
        public_key = deserialize_key(data_owner.public_key.data, pairing_group)
        new_private_key = deserialize_key(new_private_key.data, pairing_group)
        ciphertext = cp_abe.encrypt(public_key, plaintext, policy_str)
        decrypted_msg = cp_abe.decrypt(public_key, new_private_key, ciphertext)
        assert plaintext == decrypted_msg.decode("utf-8")


def test_keygen_doesnt_have_key_from_owner(client, app_and_ctx, master_key_user_two, attr_auth_access_token_one, attr_auth_access_token_two):
    data = {
        "access_token": attr_auth_access_token_two,
        "master_key": master_key_user_two,
        "attr_list": "TODAY GUEST",
        "receiver_id": "1"
    }
    app, ctx = app_and_ctx
    with app.app_context():
        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == attr_auth_access_token_one) \
            .first()  # TestUser access_token

        num_of_old_keys = len(receiver.private_keys)

        response = client.post('/attr_auth/keygen', query_string=data, follow_redirects=True)
        assert response.status_code == 200

        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == attr_auth_access_token_one) \
            .first()  # TestUser access_token
        new_private_key = next(key for key in receiver.private_keys if key.challenger_id == 2)

        assert len(receiver.private_keys) == num_of_old_keys + 1

        # Try to encrypt and decrypt
        pairing_group = create_pairing_group()
        cp_abe = create_cp_abe()
        plaintext = "Hello World"
        data_owner = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == attr_auth_access_token_two) \
            .first()
        policy_str = '(GUEST)'
        public_key = deserialize_key(data_owner.public_key.data, pairing_group)
        new_private_key = deserialize_key(new_private_key.data, pairing_group)
        ciphertext = cp_abe.encrypt(public_key, plaintext, policy_str)
        decrypted_msg = cp_abe.decrypt(public_key, new_private_key, ciphertext)
        assert plaintext == decrypted_msg.decode("utf-8")


def test_parse_attr_list():
    attr_list = 'QH QD\t JC KD 4   JS'
    empty_attr_list = ''
    invalid_attr_list = 'Q-H QD JC K_D JS'
    assert parse_attr_list(attr_list) == ['QH', 'QD', 'JC', 'KD', '4', 'JS']
    assert len(parse_attr_list(empty_attr_list)) == 0
    assert len(parse_attr_list(invalid_attr_list)) == 0


def test_replace_existing_key(app_and_ctx, attr_auth_access_token_two):
    app, ctx = app_and_ctx
    attr_list = ["TODAY", "TOMORROW"]
    dummy_serialized_key = b'key'
    with app.app_context():
        owner = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == "54agPr4edV9PvyyBNkjFfA))") \
            .first()
        receiver = db.session.query(AttrAuthUser) \
            .filter(AttrAuthUser.access_token == attr_auth_access_token_two) \
            .first()

        replace_existing_key(receiver, dummy_serialized_key, owner, attr_list)
        modified_key = receiver.private_keys[0]
        assert modified_key.data == dummy_serialized_key
        assert modified_key.attributes[0].value == "TODAY"


def test_key_setup(client, app_and_ctx, attr_auth_access_token_one):
    data = {"access_token": attr_auth_access_token_one}
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
