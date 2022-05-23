#!/usr/bin/python3
from random import randrange
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint


def pkcs7_padding(inp: bytearray, block_size: int):
    padding_byte = block_size - len(inp) % block_size
    if padding_byte == 0:
        padding_byte = block_size
    padded_inp = inp
    for _ in range(padding_byte):
        padded_inp.append(padding_byte)
    return padded_inp


def aes_ecb_enc(pt: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pt)


def fixed_xor(in1: bytearray, in2: bytearray):
    if len(in1) != len(in2):
        print("Input arrays had different lengths")
        exit(-1)
    xored = bytearray()
    for (a, b) in list(zip(in1, in2)):
        xored.append(a ^ b)
    return xored


def aes_cbc_enc(pt: bytearray, key: bytearray, iv: bytearray):
    # pad plaintext to block length, i.e. 16 bytes
    padded_pt = pkcs7_padding(pt, 16)
    # separate into blocks
    pt_blocks = [padded_pt[i * 16: (i + 1) * 16]
                 for i in range(len(padded_pt) // 16)]
    ct = bytearray()
    # set IV as "last ciphertext to be produced"
    last_ct = iv
    for block in pt_blocks:
        # XOR previous ciphertext block and current plaintext block
        pt = fixed_xor(last_ct, block)
        # Encrypt in ECB mode
        last_ct = aes_ecb_enc(bytes(pt), bytes(key))
        ct += last_ct

    return ct


# Generates random key, prefix bytes (between 5 and 10 bytes),
# postfix bytes (between 5 and 10 bytes), IV, and randomly chooses
# between ECB and CBC
def encryption_oracle(inp: bytearray):
    key = bytearray(get_random_bytes(16))
    prefix = bytearray(get_random_bytes(randint(5, 10)))
    postfix = bytearray(get_random_bytes(randint(5, 10)))
    inp = prefix + inp + postfix
    if randint(0, 1) == 0:
        # ECB path
        inp = pkcs7_padding(inp, 16)
        return aes_ecb_enc(inp, key)
    else:
        # CBC path
        return aes_cbc_enc(inp, key, bytearray(get_random_bytes(16)))


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


def detection_oracle():
    # Compose a plaintext that is easy to identify under ECB
    # This means we need at least 2 identical blocks which will encrypt to the same thing
    # Easiest value to use is just 16 * 2 = 32 bytes of 0x00.
    # However, since we have those 5-10 prefix and 5-10 postfix bytes, we need to make
    # sure we can fill up the first and last block, and still have (at least) two identical ones in the
    # middle.
    # Thus we need at least (16 - 5) * 2 + 16 * 2 = 54 bytes of 0x00 (or any other value).
    pt = bytearray([0] * 54)
    ct = encryption_oracle(pt)
    if detect_ecb(ct, 16):
        return 0
    else:
        return 1


cbc_count = 0
ecb_count = 0
for _ in range(1000):
    if detection_oracle() == 0:
        ecb_count += 1
    else:
        cbc_count += 1

print("Out of 1000 runs we got " + str(ecb_count) +
      " ECB encryptions and " + str(cbc_count) + " CBC encryptions")
