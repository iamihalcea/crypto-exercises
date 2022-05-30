#!/usr/bin/python3
from Crypto.Cipher import AES
import re

static_key = bytearray(b'U5Bag3ASTJ3KvdGw')


def pkcs7_padding(inp: bytearray, block_size: int):
    padding_byte = block_size - len(inp) % block_size
    if padding_byte == 0:
        padding_byte = block_size
    padded_inp = inp
    for _ in range(padding_byte):
        padded_inp.append(padding_byte)
    return padded_inp


def aes_ecb_enc(pt: bytearray, key: bytearray):
    if len(pt) % 16 != 0:
        pt = pkcs7_padding(pt, 16)
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    return cipher.encrypt(bytes(pt))


def aes_ecb_dec(ct, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)


def profile_for(email: str):
    email = email.replace('&', '')
    email = email.replace('=', '')
    if re.fullmatch('[a-zA-Z]+@[a-zA-Z]+\.[a-zA-Z]{1,5}', email) == None:
        print("Profile name is not an email!")
        exit(-1)
    profile_str = 'email=' + email + '&uid=10&role=user'
    ct = aes_ecb_enc(bytearray(profile_str, 'utf-8'), static_key)
    return ct


cookie = profile_for('ionut@mds.admin')[0:16] + profile_for(
    'ionut@md.amin')[16:32] + profile_for('ionut@mdc.admin')[16:32]
print(aes_ecb_dec(cookie, static_key))
