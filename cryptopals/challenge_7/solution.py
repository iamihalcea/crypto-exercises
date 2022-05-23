#!/usr/bin/python3
import os
import base64
from Crypto.Cipher import AES

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, 'input')) as f:
    in_text = f.read().replace('\n', '')


def aes_ecb_dec(ct, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)


def aes_ecb_enc(pt, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pt)


# decode base64
in_bytes = base64.b64decode(in_text)
key = b'YELLOW SUBMARINE'

with open(os.path.join(__location__, './output'), "w") as f:
    f.write(aes_ecb_dec(in_bytes, key).decode())
    f.write('\n')
