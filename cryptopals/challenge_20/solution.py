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


def solve_single_char_xor(inp: bytearray):
    freq = [[0] * 256 for _ in range(0, 256)]
    for key in range(0, 256):
        # character frequency for the current key
        for byte in inp:
            byte_x = byte ^ key
            freq[key][byte_x] += 1

    max_score = 0
    best_key = 0

    # scores per letter, more for more frequent ones
    score = [1] * 26
    score[0] = 2  # a
    score[4] = 3  # e
    score[8] = 2  # i
    score[13] = 2  # n
    score[14] = 2  # o
    score[18] = 2  # t

    for key in range(0, 255):
        curr_score = 0
        for idx in range(65, 91):  # A-Z
            # Calculate current score including both upper and lower case letters
            curr_score += freq[key][idx] * score[idx - 65] + \
                freq[key][idx + 32] * score[idx - 65]
        # add score for spaces
        curr_score += freq[key][32] * 2
        if curr_score > max_score:
            max_score = curr_score
            best_key = key

    xored_inp = bytearray()
    for byte in inp:
        xored = byte ^ best_key
        xored_inp.append(xored)
    return xored_inp


__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, 'input')) as f:
    in_text = f.readlines()

# decode base64
in_bytes = [bytearray(base64.b64decode(line)) for line in in_text]
encrypted_lines = [aes_ctr_enc(nonce, line, key) for line in in_bytes]
n_lines = len(encrypted_lines)
min_len = min([len(line) for line in encrypted_lines])

# put all the min-length chunks in one big ciphertext
encrypted_bytes = bytearray()
for line in encrypted_lines:
    encrypted_bytes += line[:min_len]

# re-arrange the bytes to group all characters xor'ed with the same key byte
rearranged_bytes = [bytearray([encrypted_bytes[i]
                               for i in range(j, len(encrypted_bytes), min_len)]) for j in range(min_len)]
# decrypt each group independently
decrypted_bytes = [solve_single_char_xor(
    subset) for subset in rearranged_bytes]
# re-assemble (part-of) the text; this will miss a few characters at the end, but meh
text = bytearray()
for group in zip(*decrypted_bytes):
    text += bytearray(group)

with open(os.path.join(__location__, './output'), "a") as f:
    f.write(text.decode())
    f.write('\n')
