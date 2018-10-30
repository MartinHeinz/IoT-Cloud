import base64
import sys

from crypto_utils import decrypt


def main():
	ciphertext = base64.b64decode(sys.argv[1])
	tag = base64.b64decode(sys.argv[2])

	key = b'f\x9c\xeb Lj\x13n\x84B\xf5S\xb5\xdfnl53d\x10\x12\x92\x82\xe1\xe3~\xc8*\x16\x9f\xd69'  # os.urandom(32)
	iv = b'HQ\xd9\xb3Kz\n\xcc\xb224Q\xdb\xc7u\xb7'  # os.urandom(16)

	data = decrypt(
		key,
		b"authenticated but not encrypted payload",
		iv,
		ciphertext,
		tag
	)
	print(data)


if __name__ == '__main__':
	main()
