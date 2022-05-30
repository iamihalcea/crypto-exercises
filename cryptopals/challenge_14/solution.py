#!/usr/bin/python3
from Crypto.Cipher import AES
import os
import base64
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

static_key = bytearray(b'zKdfx6rLw2DhfUjX')

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, 'input')) as f:
    in_text = f.read().replace('\n', '')

# decode base64
secret_bytes = bytearray(base64.b64decode(in_text))


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


def encryption_oracle(pt: bytearray):
    prefix_len = randint(1, 16)
    prefix = bytearray(get_random_bytes(prefix_len))
    new_pt = prefix + pt + secret_bytes
    return aes_ecb_enc(new_pt, static_key)


# Detects ECB by checking whether there are any two identical blocks in the input
def detect_ecb(inp: bytearray, N: int):
    # split into blocks of N bytes
    line_blocks = [inp[(i * N): ((i + 1) * N)]
                   for i in range(len(inp) // N)]
    for idx1 in range(len(line_blocks) - 1):
        for idx2 in range(idx1 + 1, len(line_blocks)):
            if line_blocks[idx1] == line_blocks[idx2]:
                return True
    return False


def find_delimiter():
    pt = b'B' * 32
    ct1 = encryption_oracle(pt)
    ct2 = encryption_oracle(pt)
    blocks1 = [ct1[(i * 16): ((i + 1) * 16)]
               for i in range(len(ct1) // 16)]
    blocks2 = [ct2[(i * 16): ((i + 1) * 16)]
               for i in range(len(ct1) // 16)]
    for block1 in blocks1:
        for block2 in blocks2:
            if block1 == block2:
                return bytearray(block1)


tbs = 16
delimiter = find_delimiter()

known_bytes = bytearray()
len_secret = len(encryption_oracle(bytearray(b'A' * tbs))) - tbs

for pos in range(tbs):
    mock_bytes_root = bytearray(b'A' * (tbs - pos - 1) + known_bytes)
    for guess in range(256):
        mock_bytes = bytearray(b'B' * 16)
        mock_bytes += bytearray(mock_bytes_root)
        mock_bytes.append(guess)
        mock_bytes += b'A' * (tbs - pos - 1)
        found_delimiter = False
        ct = None
        while not found_delimiter:
            dup_mock_bytes = bytearray(mock_bytes)
            ct = encryption_oracle(dup_mock_bytes)
            ct_blocks = [ct[(i * 16): ((i + 1) * 16)]
                         for i in range(len(ct) // 16)]
            for block in ct_blocks:
                found_delimiter |= block == delimiter
        if detect_ecb(ct, tbs):
            known_bytes.append(guess)
            break

for pos in range(len_secret - tbs):
    mock_bytes_root = known_bytes[pos + 1: pos + tbs]
    for guess in range(256):
        mock_bytes = bytearray(b'B' * 16)
        mock_bytes += bytearray(mock_bytes_root)
        mock_bytes.append(guess)
        offset = tbs - pos % tbs - 1
        mock_bytes += b'A' * offset
        found_delimiter = False
        ct = None
        while not found_delimiter:
            dup_mock_bytes = bytearray(mock_bytes)
            ct = encryption_oracle(dup_mock_bytes)
            ct_blocks = [ct[(i * 16): ((i + 1) * 16)]
                         for i in range(len(ct) // 16)]
            for block in ct_blocks:
                found_delimiter |= block == delimiter
        if detect_ecb(ct, tbs):
            known_bytes.append(guess)
            break

with open(os.path.join(__location__, './output'), "a") as f:
    f.write(known_bytes.decode('utf-8'))
