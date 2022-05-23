#!/usr/bin/python3
import os

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

with open(os.path.join(__location__, 'input')) as f:
    in_hex = f.readlines()


def fixed_xor(in1: bytearray, in2: bytearray):
    if len(in1) != len(in2):
        print("Input arrays had different lengths")
        exit(-1)
    xored = bytearray()
    for (a, b) in list(zip(in1, in2)):
        xored.append(a ^ b)
    return xored


with open(os.path.join(__location__, './output'), "w") as f:
    f.write(fixed_xor(bytearray.fromhex(
        in_hex[0]), bytearray.fromhex(in_hex[1])).hex())
