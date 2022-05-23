#!/usr/bin/python3
import os


def detect_ecb(inp: bytearray, N: int):
    # split into blocks of N bytes
    line_blocks = [inp[(i * N): ((i + 1) * N)]
                   for i in range(len(inp) // N)]
    for idx1 in range(len(line_blocks) - 1):
        for idx2 in range(idx1 + 1, len(line_blocks)):
            if line_blocks[idx1] == line_blocks[idx2]:
                return True
    return False


__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, 'input')) as f:
    in_hex = f.readlines()

# decode hex lines
in_lines = [bytearray.fromhex(line) for line in in_hex]


# find lines with duplicate 16-byte block
for count, line in enumerate(in_lines):
    if detect_ecb(line, 16):
        print("Dup in line " + str(count))
