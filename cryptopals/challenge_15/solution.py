#!/usr/bin/python3


def pkcs7_padding(inp: bytearray, block_size: int):
    padding_byte = block_size - len(inp) % block_size
    if padding_byte == 0:
        padding_byte = block_size
    padded_inp = inp
    for _ in range(padding_byte):
        padded_inp.append(padding_byte)
    return padded_inp


def check_pkcs7_padding(inp: bytearray, block_size: int):
    if len(inp) % block_size != 0:
        raise Exception("Input block has incorrect length for PKCS7 padding")
    padding_block = inp[-1]
    for idx in range(1, padding_block):
        if inp[(-1) * idx] != padding_block:
            return False
    return True


def strip_pkcs7_padding(inp: bytearray, block_size: int):
    if not check_pkcs7_padding(inp, block_size):
        raise Exception("Input block has invalid PKCS7 padding")
    padding_block = inp[-1]
    return bytearray(inp[:(-1) * padding_block])


valid_pt = pkcs7_padding(bytearray('Valid plaintext!', 'utf-8'), 16)
strip_pkcs7_padding(valid_pt, 16)
invalid_pt = bytearray(valid_pt)
invalid_pt[-1] += 2
try:
    strip_pkcs7_padding(invalid_pt, 16)
except Exception as e:
    print('Caught exception: ' + str(e))
