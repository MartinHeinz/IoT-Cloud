from flask import request

from app.attribute_authority.utils import create_attributes, parse_attr_list, get_private_key_based_on_owner, is_valid, create_private_key
from app.app_setup import db
from app.attribute_authority import attr_authority
from app.attribute_authority.utils import serialize_charm_object, create_cp_abe, create_pairing_group, deserialize_charm_object
from app.auth.utils import require_api_token, token_to_hash
from app.consts import ATTR_LIST_MISSING_ERROR_MSG, RECEIVER_ID_MISSING_ERROR_MSG, INCORRECT_RECEIVER_ID_ERROR_MSG, \
    INVALID_ATTR_LIST_ERROR_MSG, MESSAGE_MISSING_ERROR_MSG, POLICY_STRING_MISSING_ERROR_MSG, CIPHERTEXT_MISSING_ERROR_MSG, COULD_NOT_DECRYPT_ERROR_MSG, \
    INVALID_OWNER_API_USERNAME_ERROR_MSG, OWNER_API_USERNAME_MISSING_ERROR_MSG, API_USERNAME_MISSING_ERROR_MSG, DEVICE_ID_MISSING_ERROR_MSG
from app.models.models import AttrAuthUser, MasterKeypair, PrivateKey
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


@attr_authority.route('/set_username', methods=['POST'])
@require_api_token("attr_auth")
def set_username():
    token = token_to_hash(request.args.get("access_token", None))
    api_username = request.form.get("api_username", None)

    arg_check = check_missing_request_argument((api_username, API_USERNAME_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    user = AttrAuthUser.get_by_access_token(token)
    user.api_username = api_username
    db.session.add(user)
    db.session.commit()

    return http_json_response()


@attr_authority.route('/setup', methods=['GET'])  # NOTE: This is not idempotent
@require_api_token("attr_auth")
def key_setup():
    pairing_group = create_pairing_group()
    cp_abe = create_cp_abe()

    public_key, master_key = cp_abe.setup()

    # "store keypair in DB"
    token = token_to_hash(request.args.get("access_token", None))
    user = AttrAuthUser.get_by_access_token(token)
    serialized_public_key = serialize_charm_object(public_key, pairing_group)
    serialized_master_key = serialize_charm_object(master_key, pairing_group)
    user.master_keypair = MasterKeypair(data_public=serialized_public_key,
                                        data_master=serialized_master_key)
    db.session.add(user)
    db.session.commit()

    # return pk, msk
    return http_json_response(**{'public_key': serialized_public_key.decode("utf-8")})


@attr_authority.route('/user/keygen', methods=['POST'])
@require_api_token("attr_auth")
def keygen():
    token = token_to_hash(request.args.get("access_token", None))
    attr_list = request.form.get("attr_list", None)
    receiver_id = request.form.get("receiver_id", None)
    device_id = request.form.get("device_id", None)
    data_owner = AttrAuthUser.get_by_access_token(token)

    arg_check = check_missing_request_argument(
        (attr_list, ATTR_LIST_MISSING_ERROR_MSG),
        (receiver_id, RECEIVER_ID_MISSING_ERROR_MSG),
        (device_id, DEVICE_ID_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    receiver = AttrAuthUser.get_by_id(receiver_id)
    if receiver is None:
        return http_json_response(False, 400, **{"error": INCORRECT_RECEIVER_ID_ERROR_MSG})

    attr_list = parse_attr_list(attr_list)
    if not attr_list or not is_valid(attr_list, data_owner.id):
        return http_json_response(False, 400, **{"error": INVALID_ATTR_LIST_ERROR_MSG})

    serialized_private_key = create_private_key(data_owner.master_keypair.data_master,
                                                data_owner.master_keypair.data_public,
                                                attr_list)

    # delegate to receiver of generated key
    receiver.private_keys.append(PrivateKey(data=serialized_private_key,
                                            challenger=data_owner,
                                            device_id=device_id,  # TODO if key for this device exists and receiver exists, then it should overwrite
                                            attributes=create_attributes(attr_list)))
    db.session.commit()
    return http_json_response()


@attr_authority.route('/device/keygen', methods=['POST'])
@require_api_token("attr_auth")
def device_keygen():
    token = token_to_hash(request.args.get("access_token", None))
    attr_list = request.form.get("attr_list", None)
    data_owner = AttrAuthUser.get_by_access_token(token)

    arg_check = check_missing_request_argument(
        (attr_list, ATTR_LIST_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    attr_list = parse_attr_list(attr_list)
    if not attr_list or not is_valid(attr_list, data_owner.id):
        return http_json_response(False, 400, **{"error": INVALID_ATTR_LIST_ERROR_MSG})

    serialized_private_key = create_private_key(data_owner.master_keypair.data_master,
                                                data_owner.master_keypair.data_public,
                                                attr_list)

    # delegate to receiver of generated key
    return http_json_response(private_key=serialized_private_key.decode("utf-8"))


@attr_authority.route('/user/retrieve_private_keys', methods=['POST'])
@require_api_token("attr_auth")
def retrieve_private_keys():
    user_access_token = token_to_hash(request.args.get("access_token", ""))
    user = AttrAuthUser.get_by_access_token(user_access_token)
    private_keys = [{
        "data": key.data.decode("utf-8"),
        "key_update": key.key_update,
        "attributes": [a.value for a in key.attributes],
        "challenger_id": key.challenger_id,
        "device_id": key.device_id,

    } for key in user.private_keys]
    return http_json_response(**{'private_keys': private_keys})


@attr_authority.route('/encrypt', methods=['GET'])
@require_api_token("attr_auth")
def encrypt():
    token = token_to_hash(request.args.get("access_token", None))
    plaintext = request.args.get("message", None)
    policy_string = request.args.get("policy_string", None)
    # TODO can't tell if `policy_string` is valid or not based on produced ciphertext, could use pyparsing... too complex

    arg_check = check_missing_request_argument(
        (plaintext, MESSAGE_MISSING_ERROR_MSG),
        (policy_string, POLICY_STRING_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    pairing_group = create_pairing_group()
    cp_abe = create_cp_abe()
    data_owner = AttrAuthUser.get_by_access_token(token)
    public_key = deserialize_charm_object(data_owner.master_keypair.data_public, pairing_group)
    ciphertext = cp_abe.encrypt(public_key, plaintext, policy_string)

    # return ciphertext
    return http_json_response(**{'ciphertext': serialize_charm_object(ciphertext, pairing_group).decode("utf-8")})


@attr_authority.route('/decrypt', methods=['GET'])  # NOTE: ciphertext might be too long for url
@require_api_token("attr_auth")
def decrypt():
    token = token_to_hash(request.args.get("access_token", None))
    owner_api_username = request.args.get("api_username", None)
    serialized_ciphertext = request.args.get("ciphertext", None)

    arg_check = check_missing_request_argument(
        (owner_api_username, OWNER_API_USERNAME_MISSING_ERROR_MSG),
        (serialized_ciphertext, CIPHERTEXT_MISSING_ERROR_MSG))
    if arg_check is not True:
        return arg_check

    pairing_group = create_pairing_group()
    cp_abe = create_cp_abe()

    data_owner = db.session.query(AttrAuthUser) \
        .filter(AttrAuthUser.api_username == owner_api_username) \
        .first()
    if data_owner is None:
        return http_json_response(False, 400, **{"error": INVALID_OWNER_API_USERNAME_ERROR_MSG})

    decryptor = AttrAuthUser.get_by_access_token(token)
    public_key = deserialize_charm_object(data_owner.master_keypair.data_public, pairing_group)
    private_key = deserialize_charm_object(get_private_key_based_on_owner(decryptor, data_owner).data, pairing_group)
    ciphertext = deserialize_charm_object(str.encode(serialized_ciphertext), pairing_group)

    try:
        plaintext = cp_abe.decrypt(public_key, private_key, ciphertext)
    except:
        return http_json_response(False, 400, **{"error": COULD_NOT_DECRYPT_ERROR_MSG})

    # return plaintext
    return http_json_response(**{'plaintext': plaintext.decode("utf-8")})
