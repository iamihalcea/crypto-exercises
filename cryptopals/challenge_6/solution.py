#!/usr/bin/python3
import os
import base64
from operator import itemgetter

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))


def hamming(a, b):
    count = 0
    for i in zip(a, b):
        xored = i[0] ^ i[1]
        while xored > 0:
            count += xored % 2
            xored //= 2
    return count


def avg_hamming_for_len(bytes: bytes, key_len: int):
    # calculate average hamming distance for a given number of pairs
    hamming_avg_range = range(4)
    curr_hamming = 0
    for i in hamming_avg_range:
        curr_hamming += hamming(bytes[key_len * i: key_len * (i + 1)],
                                bytes[key_len * (i + 1): key_len * (i + 2)]) \
            / (key_len * len(hamming_avg_range))
    return curr_hamming


def solve_single_char_xor(inp):
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


with open(os.path.join(__location__, 'input')) as f:
    in_text = f.read().replace('\n', '')
with open(os.path.join(__location__, './output'), "w") as f:
    f.close()

# decode base64
in_bytes = base64.b64decode(in_text)
# choose key range we search for
key_len_range = range(2, 40)

# compute hamming distance for each key length and store them as tuples
hamming_per_key_len = [(key_len, avg_hamming_for_len(in_bytes, key_len))
                       for key_len in key_len_range]
# sort them ascendingly based on hamming distance
hamming_per_key_len.sort(key=itemgetter(1))

# check the best 4 lengths (based on the hamming distance)
hamming_check_range = range(4)
for idx in hamming_check_range:
    # re-arrange the bytes to group all characters xor'ed with the same key byte
    rearranged_bytes = [[in_bytes[i] for i in range(j, len(
        in_bytes), hamming_per_key_len[idx][0])] for j in range(hamming_per_key_len[idx][0])]
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
