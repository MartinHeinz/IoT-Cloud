import datetime
import re

from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup

from app.app_setup import db
from app.models.models import AttrAuthUser, Attribute


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


def get_user_by_id(user_id):
    return db.session.query(AttrAuthUser).filter(AttrAuthUser.id == user_id).first()


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
    valid = re.match('^([^_\W]|\s)+$', str_value) is not None
    if valid:
        return str_value.split()
    return []
