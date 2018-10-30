import base64

import requests

from client.crypto_utils import encrypt

key = b'f\x9c\xeb Lj\x13n\x84B\xf5S\xb5\xdfnl53d\x10\x12\x92\x82\xe1\xe3~\xc8*\x16\x9f\xd69'  # os.urandom(32)

iv, ciphertext, tag = encrypt(
    key,
    b"{'data': 'secret'}",
    b"authenticated but not encrypted payload"
)

url = "http://0.0.0.0/api/publish"
topic = "flask_test"
data = {"ciphertext": str(base64.b64encode(ciphertext), 'utf-8'), "tag": str(base64.b64encode(tag), 'utf-8'), "topic": topic}
print(data)

r = requests.post(url, params=data)
