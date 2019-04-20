import base64
import json
import os
# import pickle
import random
import secrets
import string
import time
import uuid
from datetime import datetime, timedelta

from cryptography.fernet import Fernet
from passlib.hash import bcrypt

from app.app_setup import create_app, db
from app.attribute_authority.utils import create_pairing_group, create_cp_abe, serialize_charm_object, \
    create_private_key
from app.auth.utils import generate_auth_token
from app.config import DB_SETUP_CONFIG_NAME
from app.models.models import User, MQTTUser, DeviceType, Device, Scene, DeviceData, AttrAuthUser, MasterKeypair, \
    PrivateKey, Attribute, UserDevice
from crypto_utils import correctness_hash, blind_index, instantiate_ope_cipher, pad_payload_attr, \
    encrypt_using_abe_serialized_key, int_to_bytes, key_to_hex
from password_hashing import pbkdf2_hash


def random_string(length=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def random_date(start, end):
    """
    This function will return a random datetime between two datetime
    objects.
    """
    delta = end - start
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    return start + timedelta(seconds=random_second)


def create_abe_key_pair():
    pairing_group = create_pairing_group()
    cp_abe = create_cp_abe()

    public_key, master_key = cp_abe.setup()

    serialized_public_key = serialize_charm_object(public_key, pairing_group)
    serialized_master_key = serialize_charm_object(master_key, pairing_group)

    return serialized_public_key, serialized_master_key


app = create_app(DB_SETUP_CONFIG_NAME)
app.app_context().push()

attr_auth_engine = db.get_engine(app, 'attr_auth')

seqs = db.engine.execute("SELECT sequence_name FROM information_schema.sequences").fetchall()
seq_names = [row[0] for row in seqs]

for s in seq_names:
    db.engine.execute(f"ALTER SEQUENCE {s} RESTART WITH 100;")

seqs = attr_auth_engine.execute("SELECT sequence_name FROM information_schema.sequences").fetchall()
seq_names = [row[0] for row in seqs]

for s in seq_names:
    attr_auth_engine.execute(f"ALTER SEQUENCE {s} RESTART WITH 100;")

d1 = datetime.strptime('01/01/2000', '%m/%d/%Y')
d2 = datetime.strptime('01/01/2019', '%m/%d/%Y')

user_no = 100
device_no = 3
device_data_no = 10

device_types = []
users = []
devices = []
mqtt_user_creds = []
keypairs = []

keys = {"users": {}}

for i in range(100, user_no + 100):
    username = random_string()
    access_token = secrets.token_hex(40)
    token_hash = bcrypt.using(rounds=13).hash(access_token)
    # noinspection PyArgumentList
    user = User(id=i,
                name=username,
                email=f'{username}@gmail.com',
                access_token=token_hash,
                access_token_update=random_date(d1, d2))

    mqtt_user = MQTTUser(username=f'u:{user.id}',
                         password_hash=pbkdf2_hash(username),
                         user=user)

    keys["users"][i] = {}
    keys["users"][i]["access_token"] = generate_auth_token(i, access_token).decode()

    users.append(user)
    db.session.add(user)
    db.session.add(mqtt_user)

db.session.flush()


keys["dt_desc_keys"] = {}
for i in range(100, device_no + 100):
    dt_desc_key = os.urandom(32)
    cipher = Fernet(base64.urlsafe_b64encode(dt_desc_key))
    dt_description = cipher.encrypt(int_to_bytes(device_no))
    dt = DeviceType(id=i,
                    type_id=uuid.uuid4(),
                    description=dt_description,
                    correctness_hash=correctness_hash(str(device_no)))

    device_types.append(dt)
    db.session.add(dt)

    keys["dt_desc_keys"][i] = key_to_hex(dt_desc_key)

for user in users:
    user.create_mqtt_creds_for_user(user.mqtt_creds.password_hash, db.session)

    keys["users"][user.id]["devices"] = {}
    keys["users"][user.id]["actions"] = {}
    keys["users"][user.id]["aa_secret_keys"] = {}

    for i in range(100, device_no + 100):  # 3 devices per user
        dv_bi_key = os.urandom(32)
        dv_name_key = os.urandom(32)
        cipher = Fernet(base64.urlsafe_b64encode(dv_name_key))
        dv_name = cipher.encrypt(int_to_bytes(device_no))

        dv_status_key = os.urandom(32)
        cipher = Fernet(base64.urlsafe_b64encode(dv_status_key))
        dv_status = cipher.encrypt(int_to_bytes(0))
        # noinspection PyArgumentList
        dv = Device(status=dv_status,
                    device_type_id=random.choice(device_types).id,
                    name=dv_name,
                    name_bi=blind_index(dv_bi_key, str(i)),
                    correctness_hash=correctness_hash(str(i)),
                    owner=user)

        ud = UserDevice()
        ud.device = dv
        ud.user = user
        user.devices.append(ud)

        db.session.add(dv)
        db.session.flush()

        keys["users"][user.id]["devices"][dv.id] = {}
        keys["users"][user.id]["devices"][dv.id]["dv_bi_key"] = key_to_hex(dv_bi_key)
        keys["users"][user.id]["devices"][dv.id]["dv_name_key"] = key_to_hex(dv_name_key)
        keys["users"][user.id]["devices"][dv.id]["dv_status_key"] = key_to_hex(dv_status_key)

        dv.create_mqtt_creds_for_device(pbkdf2_hash(str(i)), db.session)
        user.add_acls_for_device(dv.id)

        action_name_key = os.urandom(32)
        action_name_cipher = Fernet(base64.urlsafe_b64encode(action_name_key))

        keys["users"][user.id]["actions"][dv.id] = {}
        keys["users"][user.id]["actions"][dv.id]["action_name_key"] = key_to_hex(action_name_key)

        dv.add_action(action_name_cipher.encrypt(b"On"), blind_index(dv_bi_key, "On"), correctness_hash("On"))
        dv.add_action(action_name_cipher.encrypt(b"Off"), blind_index(dv_bi_key, "Off"), correctness_hash("Off"))

        dd_added_key = os.urandom(32)
        dd_added_cipher = instantiate_ope_cipher(dd_added_key)
        dd_num_data_key = os.urandom(32)
        dd_num_data_cipher = instantiate_ope_cipher(dd_num_data_key)
        abe_keypair = create_abe_key_pair()
        keypairs.append(abe_keypair)
        policy_string = f"(U-{user.id}-D-{dv.id} OR U-{user.id}-GUEST OR U-{user.id})"
        dd_tid_key = os.urandom(32)
        dd_tid_cipher = Fernet(base64.urlsafe_b64encode(dd_tid_key))

        keys["users"][user.id]["devices"][dv.id]["dd_added_key"] = key_to_hex(dd_added_key)
        keys["users"][user.id]["devices"][dv.id]["dd_num_data_key"] = key_to_hex(dd_num_data_key)
        keys["users"][user.id]["devices"][dv.id]["dd_tid_key"] = key_to_hex(dd_tid_key)
        keys["users"][user.id]["devices"][dv.id]["abe_keypair"] = {
            "public_key": abe_keypair[0].decode("utf-8"),
            "master_key": abe_keypair[1].decode("utf-8"),
            "policy": policy_string
        }

        for j in range(100, device_data_no + 100):
            dd_added = dd_added_cipher.encrypt(int(time.mktime(random_date(d1, d2).timetuple())))
            dd_num_data = dd_num_data_cipher.encrypt(j)
            dd_value = pad_payload_attr(f"{j}")
            dd_data = encrypt_using_abe_serialized_key(abe_keypair[0].decode(), dd_value, policy_string).encode()
            dd_tid = dd_tid_cipher.encrypt(int_to_bytes(j))

            # noinspection PyArgumentList
            dd = DeviceData(added=dd_added, data=dd_data, device_id=dv.id, num_data=dd_num_data, tid=dd_tid,
                            tid_bi=blind_index(dv_bi_key, str(j)),
                            correctness_hash=correctness_hash(
                                str(int(time.mktime(random_date(d1, d2).timetuple()))),
                                dd_value,
                                str(j), str(j)))

            dv.data.append(dd)
            db.session.add(dd)

        devices.append(dv)
        db.session.flush()


for i, user in enumerate(users):
    user_bi_key = os.urandom(32)

    keys["users"][user.id]["global"] = {}
    keys["users"][user.id]["global"]["user_bi_key"] = key_to_hex(user_bi_key)

    sc_name_key = os.urandom(32)
    sc_name_cipher = Fernet(base64.urlsafe_b64encode(sc_name_key))
    sc_name = sc_name_cipher.encrypt(int_to_bytes(user.id))

    keys["users"][user.id]["scenes"] = {}
    keys["users"][user.id]["scenes"]["sc_name_key"] = key_to_hex(sc_name_key)

    sc_desc_key = os.urandom(32)
    sc_desc_cipher = Fernet(base64.urlsafe_b64encode(sc_desc_key))
    sc_description = sc_desc_cipher.encrypt(int_to_bytes(user.id))

    keys["users"][user.id]["scenes"]["sc_desc_key"] = key_to_hex(sc_desc_key)

    sc = Scene(name=sc_name,
               description=sc_description,
               correctness_hash=correctness_hash(str(user.id), str(user.id)),
               name_bi=blind_index(user_bi_key, str(user.id)))

    uds = random.sample(user.devices, 2)
    for ud in uds:
        sc.actions.append(random.choice(ud.device.actions))


# pickle.dump(users, open("users.p", "wb"))

db.session.add_all(users)
db.session.add_all(device_types)
db.session.add_all(devices)
db.session.commit()


aa_users = []

for i, user in enumerate(users):
    access_token = random_string()
    token_hash = bcrypt.using(rounds=13).hash(access_token)
    # noinspection PyArgumentList
    aa_user = AttrAuthUser(name=user.name,
                           id=user.id,
                           access_token=token_hash,
                           access_token_update=random_date(d1, d2),
                           api_username=user.name)
    keypair = MasterKeypair(data_public=keypairs[i][0],
                            data_master=keypairs[i][1],
                            attr_auth_user=aa_user)

    keys["users"][user.id]["aa_access_token"] = generate_auth_token(user.id, access_token).decode()

    db.session.add(aa_user)
    db.session.add(keypair)
    db.session.flush()

    attr_list = [f"U-{user.id}",
                 f"U-{user.id}-D-{user.owned_devices[0].id}",
                 f"U-{user.id}-GUEST"]
    private_key = create_private_key(keypairs[i][1], keypairs[i][0], attr_list)
    private_key_obj = PrivateKey(data=private_key,
                                 challenger_id=aa_user.id,
                                 user_id=user.id+1 if user.id+1 < len(users) else 100,
                                 device_id=user.owned_devices[0].id,
                                 attributes=[Attribute(value=attr) for attr in attr_list])

    db.session.add(private_key_obj)

    keys["users"][user.id]["aa_secret_keys"][user.id] = private_key.decode("utf-8")
    aa_users.append(aa_user)

mqtt_admin_user = MQTTUser(username='admin',
                           superuser=1,
                           password_hash=pbkdf2_hash("password"))

db.session.add(mqtt_admin_user)

aa_users.append(mqtt_admin_user)
# pickle.dump(aa_users, open("aa_users.p", "wb"))  # NOTE: Instead of pickling data, create DB dump and use raw sql inserts.

with open('keys.json', 'w') as outfile:
    json.dump(keys, outfile, indent=4)


seqs = db.engine.execute("SELECT sequence_name FROM information_schema.sequences").fetchall()
seq_names = [row[0] for row in seqs]

for s in seq_names:
    db.engine.execute(f"ALTER SEQUENCE {s} RESTART WITH 10000;")

db.session.commit()

# SELECT count(*) FROM acl;  -- 2600
# SELECT count(*) FROM action;  -- 600
# SELECT count(*) FROM device;  -- 300
# SELECT count(*) FROM device_data;  -- 3000
# SELECT count(*) FROM device_type;  -- 3
# SELECT count(*) FROM mqtt_user;  -- 401
# SELECT count(*) FROM scene;  -- 100
# SELECT count(*) FROM scene_action;  -- 200
# SELECT count(*) FROM public."user"; -- 100
# SELECT count(*) FROM user_device;  -- 300
