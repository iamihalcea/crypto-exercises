#!/usr/bin/python3
import os

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

with open(os.path.join(__location__, 'input')) as f:
    in_hex = f.readlines()

# group together the corresponding bytes from each input array (can handle more than 2)
grouped_bytes = zip(*[bytearray.fromhex(line) for line in in_hex])
xored_bytes = bytearray()
for byte_list in grouped_bytes:
    xored = 0
    for byte in byte_list:
        xored ^= byte
    xored_bytes.append(xored)

with open(os.path.join(__location__, './output'), "w") as f:
    f.write(xored_bytes.hex())
    