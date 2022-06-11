#!/usr/bin/python3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

prefix = bytearray('comment1=cooking%20MCs;userdata=', 'utf-8')
postfix = bytearray(';comment2=%20like%20a%20pound%20of%20bacon', 'utf-8')
secret_key = bytearray('my9ekeKDS9ti68tk', 'utf-8')


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
        print("Wrong input type for PKCS#7 padding")
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
        print("Input did not have proper PKCS#7 padding")
        exit(-1)
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


def encryption_oracle(inp: bytearray):
    pt = prefix + inp + postfix
    pt = pkcs7_padding(pt, 16)
    iv = get_random_bytes(16)
    return (iv, aes_cbc_enc(pt, secret_key, iv))


def is_admin(iv: bytearray, inp: bytearray):
    pt = aes_cbc_dec(inp, secret_key, iv)
    try:
        pt = pt.decode('utf-8')
    except Exception as e:
        # print("Got exception trying to parse plaintext as UTF-8: " + str(e))
        return False
    props = pt.split(';')
    tokens = {}
    for prop in props:
        prop_parts = prop.split('=', 1)
        if len(prop_parts) != 2:
            continue
        tokens[prop_parts[0]] = prop_parts[1]
    if 'admin' in tokens and tokens['admin'] == 'true':
        return True
    return False


original_chunk = bytearray(';comment2=%2', 'utf-8')
desired_chunk = bytearray(';admin=true;', 'utf-8')
xor_chunk = [a ^ b for (a, b) in zip(original_chunk, desired_chunk)]
found_it = False
ct = None
while not found_it:
    random_bytes = bytearray(get_random_bytes(16))
    (iv, ct) = encryption_oracle(random_bytes)
    for idx in range(len(xor_chunk)):
        ct[32 + idx] ^= xor_chunk[idx]
    found_it = is_admin(iv, ct)

print("Success! Token was: '" + aes_cbc_dec(ct,
      secret_key, iv).decode('utf-8') + "'")
