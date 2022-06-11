#!/usr/bin/python3
import os
import base64
from Crypto.Cipher import AES


def aes_ecb_enc(pt: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pt)


def variable_xor(in1: bytearray, in2: bytearray):
    xored = bytearray()
    for (a, b) in list(zip(in1, in2)):
        xored.append(a ^ b)
    return xored


def increment_ctr(ctr: bytearray):
    idx = 0
    while ctr[idx] == 255 and idx < len(ctr):
        ctr[idx] = 0
        idx += 1
    if idx < len(ctr):
        ctr[idx] += 1


def aes_ctr_enc(nonce: bytearray, pt: bytearray, key: bytearray) -> bytearray:
    if len(nonce) != 8:
        raise Exception("Nonce has invalid size")
    # separate into blocks
    pt_blocks = [pt[i * 16: (i + 1) * 16]
                 for i in range(len(pt) // 16)]
    if len(pt) % 16 != 0:
        pt_blocks.append(bytearray(pt[(len(pt) // 16) * 16:]))
    ct = bytearray()
    ctr = bytearray([0] * 8)
    for block in pt_blocks:
        inp = bytearray(nonce) + ctr
        keystream = bytearray(aes_ecb_enc(bytes(inp), bytes(key)))
        ct += variable_xor(keystream, block)
        increment_ctr(ctr)

    return ct


def aes_ctr_dec(nonce: bytearray, ct: bytearray, key: bytearray) -> bytearray:
    if len(nonce) != 8:
        raise Exception("Nonce has invalid size")
    # separate into blocks
    ct_blocks = [ct[i * 16: (i + 1) * 16]
                 for i in range(len(ct) // 16)]
    if len(ct) % 16 != 0:
        ct_blocks.append(bytearray(ct[(len(ct) // 16) * 16:]))
    pt = bytearray()
    ctr = bytearray([0] * 8)
    for block in ct_blocks:
        inp = bytearray(nonce) + ctr
        keystream = bytearray(aes_ecb_enc(bytes(inp), bytes(key)))
        pt += variable_xor(keystream, block)
        increment_ctr(ctr)

    return pt


__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, 'input')) as f:
    in_text = f.read().replace('\n', '')

# decode base64
in_bytes = bytearray(base64.b64decode(in_text))

key = bytearray('YELLOW SUBMARINE', 'utf-8')
nonce = bytearray([0] * 8)
with open(os.path.join(__location__, './output'), "a") as f:
    f.write(aes_ctr_dec(nonce, in_bytes, key).decode('utf-8'))
    f.write('\n')
