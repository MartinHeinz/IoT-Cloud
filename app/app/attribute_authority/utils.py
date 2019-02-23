import datetime
import re

from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup

from app.models.models import Attribute


def serialize_charm_object(key, group):
    return objectToBytes(key, group)


def deserialize_charm_object(key, group):
    return bytesToObject(key, group)


def create_pairing_group():
    """ Instantiate a bilinear pairing map """
    return PairingGroup('MNT224')


def create_cp_abe():
    pairing_group = create_pairing_group()
    cpabe = CPabe_BSW07(pairing_group)
    return HybridABEnc(cpabe, pairing_group)


def already_has_key_from_owner(receiver, owner):
    for key in receiver.private_keys:
        if key.challenger == owner:
            return True
    return False


def replace_existing_key(receiver, new_key, owner, attr_list):
    for key in receiver.private_keys:
        if key.challenger == owner:
            key.data = new_key
            key.key_update = datetime.datetime.now()
            key.attributes = create_attributes(attr_list)


def create_attributes(attr_list):
    result = []
    for attr in attr_list:
        result.append(Attribute(value=attr))
    return result


def parse_attr_list(str_value):
    valid = re.match(r'^([^_\W]|\s|-)+$', str_value) is not None
    if valid:
        return str_value.split()
    return []


def get_private_key_based_on_owner(decryptor, owner):
    for key in decryptor.private_keys:
        if key.challenger == owner:
            return key
    raise Exception("Decryptor doesn't have any key from specified owner.")


def is_valid(attr_list, do_id):
    for attr in attr_list:
        if not attr == str(do_id) and not attr.startswith(str(do_id) + "-"):
            return False
    return True


def create_private_key(serialized_master_key, serialized_public_key, attr_list):
    group = create_pairing_group()
    master_key = deserialize_charm_object(serialized_master_key, group)
    cp_abe = create_cp_abe()

    public_key = deserialize_charm_object(serialized_public_key, group)
    private_key = cp_abe.keygen(public_key, master_key, attr_list)
    return serialize_charm_object(private_key, group)
