#!/usr/bin/python3
import os

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

key = b'ICE'
with open(os.path.join(__location__, 'input')) as f:
    in_text = f.readlines()
with open(os.path.join(__location__, './output'), "w") as f:
    f.close()

key_idx = 0
for line in in_text: 
    xored_bytes = bytearray()
    for byte in bytearray(line, 'utf-8'):
        xored = byte ^ key[key_idx]
        key_idx += 1
        key_idx %= len(key)
        xored_bytes.append(xored)

    with open(os.path.join(__location__, './output'), "a") as f:
        f.write(xored_bytes.hex())
    