#!/usr/bin/python3
import base64
import os

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

with open(os.path.join(__location__, 'input')) as f:
    in_hex = f.readlines()

for line in in_hex:
    with open(os.path.join(__location__, './output'), "w") as f:
        f.write(base64.b64encode(bytes.fromhex(line)).decode('utf-8'))