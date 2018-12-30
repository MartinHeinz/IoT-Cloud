from flask import request

from app.api.utils import is_number
from app.attribute_authority.utils import already_has_key_from_owner, replace_existing_key, create_attributes, parse_attr_list
from app.app_setup import db
from app.attribute_authority import attr_authority
from app.attribute_authority.utils import serialize_key, create_cp_abe, create_pairing_group, deserialize_key, get_user_by_id
from app.auth.utils import require_api_token
from app.models.models import AttrAuthUser, PublicKey, PrivateKey
from app.utils import http_json_response, check_missing_request_argument

"""
NOTES:
- To create revocation, we need to re-encrypt data with new policy_str,
    which needs to remove attributes, that are no longer valid
- Using ac17 - based on https://eprint.iacr.org/2017/807.pdf
- This module will need a separate authentication.
    - Therefore it will need own database or at least isolated tables in existing DB
    - DB will store users and their PK(s?)
- DB will store PKs, generated secret keys (from keygen)?, user info
    
- (pk, msk) = cpabe.setup()
    - ran for every user
    - PK stored in DB
    - msk is Master SECRET key -> it needs to be securely transfered to user and not stored on server
    
- key = cpabe.keygen(pk, msk, attr_list)
    - Owner (Challenger) needs to supply msk from previous step (stored locally)
    - generated key is then send to user with attributes == attr_list
    
- ctxt = cpabe.encrypt(pk, msg, policy_str)
    - anybody with access to pk can encrypt (This can be public endpoint = no login required)

- rec_msg = cpabe.decrypt(pk, ctxt, key)
    - Authority is trusted, so if we assume a secure connection, then we can decrypt on server,
        but can be done on client too - that will require a user to have ABE, pbc and Charm installed though
"""

MASTER_KEY_MISSING_ERROR_MSG = 'Missing serialized master key argument.'
ATTR_LIST_MISSING_ERROR_MSG = 'Missing attribute list argument.'
RECEIVER_ID_MISSING_ERROR_MSG = 'Missing receiver id argument.'
INCORRECT_RECEIVER_ID_ERROR_MSG = 'Incorrect receiver ID.'
INVALID_ATTR_LIST_ERROR_MSG = 'Invalid attribute list (only alphanumeric values separated with whitespaces are allowed).'


@attr_authority.route('/setup', methods=['POST'])
@require_api_token("attr_auth")
def key_setup():
    pairing_group = create_pairing_group()
    cp_abe = create_cp_abe()

    public_key, master_key = cp_abe.setup()

    # "store PK in DB"
    token = request.args.get("access_token", None)
    user = db.session.query(AttrAuthUser).filter(AttrAuthUser.access_token == token).first()
    serialized_public_key = serialize_key(public_key, pairing_group)
    serialized_master_key = serialize_key(master_key, pairing_group)
    user.public_key = PublicKey(data=serialized_public_key)
    db.session.add(user)
    db.session.commit()

    # return pk, msk
    return http_json_response(**{'public_key': serialized_public_key.decode("utf-8"), 'master_key': serialized_master_key.decode("utf-8")})


@attr_authority.route('/keygen', methods=['POST'])
@require_api_token("attr_auth")
def keygen():  # TODO test
    token = request.args.get("access_token", None)
    serialized_master_key = request.args.get("master_key", None)
    attr_list = request.args.get("attr_list", None)
    receiver_id = request.args.get("receiver_id", None)

    arg_check = check_missing_request_argument(
        (serialized_master_key, MASTER_KEY_MISSING_ERROR_MSG),
        (attr_list, ATTR_LIST_MISSING_ERROR_MSG),
        (receiver_id, RECEIVER_ID_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    receiver = get_user_by_id(int(receiver_id) if is_number(receiver_id) else 0)
    if receiver is None:
        return http_json_response(False, 400, **{"error": INCORRECT_RECEIVER_ID_ERROR_MSG})

    attr_list = parse_attr_list(attr_list)
    if len(attr_list) == 0:
        return http_json_response(False, 400, **{"error": INVALID_ATTR_LIST_ERROR_MSG})

    master_key = deserialize_key(str.encode(serialized_master_key), create_pairing_group())  # TODO check `serialized_master_key` before using `str.encode()`
    cp_abe = create_cp_abe()

    data_owner = db.session.query(AttrAuthUser).filter(AttrAuthUser.access_token == token).first()  # TODO test remaining lines in this function
    public_key = deserialize_key(data_owner.public_key.data, create_pairing_group())
    private_key = cp_abe.keygen(public_key, master_key, attr_list)
    serialized_private_key = serialize_key(private_key, create_pairing_group())

    # delegate to receiver of generated key
    if already_has_key_from_owner(receiver, data_owner):
        replace_existing_key(receiver, serialized_private_key, data_owner, attr_list)
    else:
        receiver.private_keys.append(PrivateKey(data=serialized_private_key,
                                                challenger=data_owner,
                                                attributes=create_attributes(attr_list)))
    db.session.commit()
    return http_json_response()


@attr_authority.route('/encrypt', methods=['POST'])
def encrypt():
    token = request.args.get("access_token", None)
    policy_str = request.args.get("policy_str")
    message = request.args.get("message")
    public_key = deserialize_key(db.session.query(AttrAuthUser).filter(AttrAuthUser.access_token == token).first().public_key.data, create_pairing_group())
    cp_abe = create_cp_abe()

    ciphertext = cp_abe.encrypt(public_key, message, policy_str)
    # return ciphertext
    return http_json_response(**{'ciphertext': ciphertext})


@attr_authority.route('/decrypt', methods=['POST'])
def decrypt():
    key = request.args.get("key")
    # pk = request.args.get("pk")
    ciphertext = request.args.get("ciphertext")

    # plaintext = cpabe.decrypt(pk, ciphertext, key)
    # return plaintext
