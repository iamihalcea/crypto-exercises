#!/usr/bin/python3
import os


def pkcs7_padding(inp: bytearray, block_size: int):
    padding_byte = block_size - len(inp) % block_size
    if padding_byte == 0:
        padding_byte = block_size
    padded_inp = inp
    for _ in range(padding_byte):
        padded_inp.append(padding_byte)
    return padded_inp


__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, 'input')) as f:
    inp = bytearray(f.readline(), 'utf-8')

print(pkcs7_padding(inp, 20))
