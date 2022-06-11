#!/usr/bin/python3
import os
import base64
from Crypto.Cipher import AES

key = bytearray('YELLOW SUBMARINE', 'utf-8')
nonce = bytearray([0] * 8)


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


__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, 'input')) as f:
    in_text = f.readlines()

# decode base64
in_bytes = [bytearray(base64.b64decode(line)) for line in in_text]
encrypted_lines = [aes_ctr_enc(nonce, line, key) for line in in_bytes]
n_lines = len(encrypted_lines)
min_len = min([len(line) for line in encrypted_lines])

# prepare buffer for decryption
decrypted_lines = [bytearray([35] * min_len) for _ in range(len(in_bytes))]

# store a version of each combination of two lines XORed with each other
# the approach below doesn't actually need it all, we just need the first
# line XORed with all the rest
xored_cts = [[bytearray([x ^ y for (x, y) in zip(encrypted_lines[idx1], encrypted_lines[idx2])])
              for idx2 in range(n_lines)] for idx1 in range(n_lines)]

# array holding all the characters that we expect in the text
characters = bytearray(
    b'etaoinshrdlcumwfgypbvkjxqzEARIOTNSLCUDPMHGBFYWKVXZJQ .,\'-')

# For each character in the first part of each message...
for idx in range(min_len):
    # try to go through the possible values that could feasibly be in that spot
    # in the first message...
    for char in characters:
        found = True
        # then assuming that was the correct character, retrieve all the other
        # characters from the remaining messages, using the XOR with the first
        # message.
        for ct_idx in range(1, n_lines):
            # If one of the messages turns up to have a "weird", unexpected character
            # somewhere...
            if characters.find(xored_cts[0][ct_idx][idx] ^ char) == -1:
                # this was probably a poor guess for the character in the first
                # message. Try with another.
                found = False
                break
        # If this is the one...
        if found:
            # set the "decrypted" value for every message
            decrypted_lines[0][idx] = char
            for ct_idx in range(1, n_lines):
                decrypted_lines[ct_idx][idx] = xored_cts[0][ct_idx][idx] ^ char
            break


with open(os.path.join(__location__, './output'), "a") as f:
    for line in decrypted_lines:
        f.write(line.decode('utf-8'))
        f.write('\n')
