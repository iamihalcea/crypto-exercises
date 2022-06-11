#!/usr/bin/python3
import os
import base64
from Crypto.Random import get_random_bytes
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Random.random import randint

key = bytearray('MvCfkzG3UusHX6X6', 'utf-8')


__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
with open(os.path.join(__location__, 'input')) as f:
    in_text = f.readlines()

# decode base64
in_bytes = [bytearray(base64.b64decode(line)) for line in in_text]


def rand_line() -> bytearray:
    idx = randint(0, 9)
    return in_bytes[idx]


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
        print("Wrong input size for PKCS#7 padding")
        exit(-1)
    padding_block = inp[-1]
    if padding_block == 0:
        return False
    for idx in range(1, padding_block + 1):
        if inp[(-1) * idx] != padding_block:
            return False
    return True


def strip_pkcs7_padding(inp: bytearray, block_size):
    if not check_pkcs7_padding(inp, block_size):
        # print("Input did not have proper PKCS#7 padding")
        raise Exception("Input block has invalid padding")
    padding_block = inp[-1]
    return inp[:(-1) * padding_block]


def aes_ecb_dec(ct: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)


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


def aes_cbc_enc(pt: bytearray, key: bytearray) -> Tuple[bytearray, bytearray]:
    # get random IV
    iv = get_random_bytes(16)
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

    return (iv, ct)


def aes_cbc_dec(ct: bytearray, key: bytearray, iv: bytearray):
    # check that the ciphertext has the correct length
    if len(ct) % 16 != 0:
        print("Wrong ciphertext size")
        exit(-1)
    # separate into blocks
    ct_blocks = [ct[i * 16: (i + 1) * 16] for i in range(len(ct) // 16)]
    pt = bytearray()
    # set IV as "last ciphertext to be produced"
    last_ct = iv
    for block in ct_blocks:
        # Encrypt in ECB mode
        masked_pt = aes_ecb_dec(bytes(block), bytes(key))
        # XOR previous ciphertext block and current (masked) plaintext block
        pt += fixed_xor(masked_pt, last_ct)
        # hold onto previous ciphertext block
        last_ct = block
    return strip_pkcs7_padding(pt, 16)


def padding_oracle(ct: bytearray) -> bool:
    try:
        aes_cbc_dec(ct, key, [0] * 16)
    except Exception:
        return False
    return True


with open(os.path.join(__location__, './output'), "w") as f:
    # go through each plaintext in the given list
    for pt in in_bytes:
        # encrypt it
        (iv, ct) = aes_cbc_enc(pt, key)
        len_ct = len(ct)
        # we'll need to operate on IV + ciphertext as if they're one (so using [0; 16] as mock IV)
        # to perform the whole attack in one go
        ct = iv + ct
        # separate ciphertext into blocks
        ct_blocks = [ct[i * 16: (i + 1) * 16] for i in range(len(ct) // 16)]
        decrypted = bytearray()
        # we take the ciphertext block by block (starting from the end)
        for block_idx in range(-1, -1 * len(ct_blocks), -1):
            # assemble the parts of the ciphertext we need
            ct = bytearray()
            for block in ct_blocks[:block_idx]:
                ct += block
            ct += ct_blocks[block_idx]

            decrypted_ct = bytearray()
            # for each byte in the last block of the assembled ciphertext (going backwards)...
            for idx in range(-1, -17, -1):
                # we expect the pad to reach to that byte and to be of pad_byte value...
                pad_byte = 16 - (idx % 16)

                # make the rest of the pad have the correct value...
                idx_ct = bytearray(ct)
                for decrypted_idx in range(len(decrypted_ct)):
                    idx_ct[-17 - decrypted_idx] ^= decrypted_ct[decrypted_idx] ^ pad_byte

                found_byte = False
                # and then we try to find which value produces a valid pad!
                # These last two steps have to act on the second-to-last block,
                # so that when XOR'ed with the plaintext of the last block,
                # we alter it in a controlled way.
                for guess in range(0, 255):
                    guess_ct = bytearray(idx_ct)
                    guess_ct[idx - 16] ^= guess
                    if padding_oracle(guess_ct) and not (guess == 0 and idx == -1):
                        decrypted_ct.append(guess ^ pad_byte)
                        found_byte = True
                        break
                if not found_byte:
                    print("Failed to find byte " + str(idx) +
                          " of block " + str(block_idx))
                    exit(-1)
            decrypted += decrypted_ct

        # Reverse the string we found
        decrypted.reverse()
        # And print it
        f.write(strip_pkcs7_padding(decrypted, 16).decode('utf-8'))
        f.write('\n')
