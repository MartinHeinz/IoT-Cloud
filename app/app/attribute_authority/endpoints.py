from app.attribute_authority import attr_authority

"""
NOTES:
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
    - Authority is trusted, so if assume a secure connection, then we can decrypt on server,
        but can be done on client too - that will require a user to have ABE, pbc and Charm installed though

"""


# TODO requires authentication
@attr_authority.route('/setup', methods=['POST'])
def key_setup():
    pass
    # (pk, msk) = cpabe.setup()
    # "store PK in DB"
    # return pk, msk


# TODO requires authentication
@attr_authority.route('/keygen', methods=['POST'])
def keygen():
    pass
    # msk = request.args.get("msk")
    # attr_list = request.args.get("attr_list")
    # key = cpabe.keygen(pk, msk, attr_list)
    # "delegate to receiver of generated key" (or send to user that requested generation of the key and let him send the key to receiver)


@attr_authority.route('/encrypt', methods=['POST'])
def encrypt():
    pass
    # policy_str = request.args.get("policy_str")
    # message = request.args.get("message")
    # "Either get PK from user (request.args...) or from DB"
    # ciphertext = cpabe.encrypt(pk, message, policy_str)
    # return ciphertext


@attr_authority.route('/decrypt', methods=['POST'])
def decrypt():
    pass
    # key = request.args.get("key")
    # pk = request.args.get("pk")
    # ciphertext = request.args.get("ciphertext")
    # plaintext = cpabe.decrypt(pk, ciphertext, key)
    # return plaintext
