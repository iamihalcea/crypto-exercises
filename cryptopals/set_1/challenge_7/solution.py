#!/usr/bin/python3
import os
import base64
from operator import itemgetter
from Crypto.Cipher import AES

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, 'input')) as f:
    in_text = f.read().replace('\n', '')

# decode base64
in_bytes = base64.b64decode(in_text)
key = b'YELLOW SUBMARINE'
cipher = AES.new(key, AES.MODE_ECB)
with open(os.path.join(__location__, './output'), "w") as f:
    f.write(cipher.decrypt(in_bytes).decode())
    f.write('\n')