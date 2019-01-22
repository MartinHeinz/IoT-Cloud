from timeit import default_timer as timer

from pyope.ope import OPE
random_key = OPE.generate_key()
cipher = OPE(random_key)

ciphertexts = []
num = 1000

start = timer()
for value in range(num):
    ciphertexts.append(cipher.encrypt(value))

end = timer()
print(f"OPE Encryption time for {num} values: {end - start}")


start = timer()
for c in ciphertexts:
    cipher.decrypt(c)

end = timer()
print(f"OPE Decryption time for {num} values: {end - start}")
