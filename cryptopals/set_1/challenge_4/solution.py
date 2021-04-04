#!/usr/bin/python3
import os

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

with open(os.path.join(__location__, 'input')) as f:
    in_hex = f.readlines()
with open(os.path.join(__location__, './output'), "w") as f:
    f.close()

in_lines = [bytearray.fromhex(line) for line in in_hex]
for in_bytes in in_lines:
    freq = [[0] * 256 for _ in range(0,256)]
    for key in range(0, 256):
        # character frequency for the current key
        for byte in in_bytes:
            byte_x = byte ^ key
            freq[key][byte_x] += 1

    max_score = 0
    best_key = 0

    # scores per letter, more for more frequent ones
    score = [1] * 26
    score[0] = 2 # a
    score[4] = 3 # e
    score[8] = 2 # i
    score[13] = 2 # n
    score[14] = 2 # o
    score[18] = 2 # t

    for key in range(0, 255):
        curr_score = 0
        for idx in range(65,91): # A-Z
            # Calculate current score including both upper and lower case letters
            curr_score += freq[key][idx] * score[idx - 65] + freq[key][idx + 32] * score[idx - 65]
        # add score for spaces
        curr_score += freq[key][32] * 2
        if curr_score > max_score:
            max_score = curr_score
            best_key = key

    print(best_key, max_score)

    xored_bytes = bytearray()
    for byte in in_bytes:
        xored = byte ^ best_key
        xored_bytes.append(xored)

    with open(os.path.join(__location__, './output'), "a") as f:
        try:
            f.write(xored_bytes.decode())
            f.write('\n')
        except UnicodeDecodeError as e:
            print(e)
    