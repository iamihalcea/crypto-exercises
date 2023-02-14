#!/usr/bin/python3
from random import randint
import time
from typing import List


def lowest_bits(x: int, w: int) -> int:
    mask = (1 << w) - 1
    return x & mask


class MT:
    def __init__(self) -> None:
        # MT19937 params
        (self.w, self.n, self.m, self.r) = (32, 624, 397, 31)
        self.a = 0x9908B0DF
        (self.u, self.d) = (11, 0xFFFFFFFF)
        (self.s, self.b) = (7, 0x9D2C5680)
        (self.t, self.c) = (15, 0xEFC60000)
        self.l = 18
        self.f = 1812433253

        self.buffer = [0] * self.n
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = lowest_bits(~self.lower_mask, self.w)

    def seed_buffer(self, seed: int):
        self.index = self.n
        self.buffer[0] = seed
        for idx in range(1, self.n):
            self.buffer[idx] = lowest_bits(
                self.f * (self.buffer[idx - 1] ^ (self.buffer[idx - 1] >> (self.w - 2))) + 1, self.w)

    def extract_number(self) -> int:
        if self.index >= self.n:
            if self.index > self.n:
                self.seed_buffer(5489)
            self.twist()

        y = self.buffer[self.index]
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= y >> self.l

        self.index += 1
        return lowest_bits(y, self.w)

    def twist(self):
        for idx in range(self.n):
            x = (self.buffer[idx] & self.upper_mask) + \
                (self.buffer[(idx + 1) % self.n] & self.lower_mask)
            xA = x >> 1
            if x % 2 == 1:
                xA ^= self.a
            self.buffer[idx] = self.buffer[(idx + self.m) % self.n] ^ xA
        self.index = 0


class UntemperedMT:
    def __init__(self) -> None:
        self.mt = MT()

    def clone_mt(self, outputs: List[int]) -> MT:
        if len(outputs) != self.mt.n:
            raise Exception('Wrong length of output array')
        for (idx, output) in enumerate(outputs):
            untampered = self.untemper_output(output)
            self.mt.buffer[idx] = untampered
        self.mt.index = self.mt.n
        return self.mt

    def untemper_output(self, output: int) -> int:
        # untempering: y ^= y >> self.l
        output = UntemperedMT.untemper_right(output, self.mt.l, (1 << 32) - 1)
        # untempering: y ^= (y << self.t) & self.c
        output = UntemperedMT.untemper_left(output, self.mt.t, self.mt.c)
        # untempering: y ^= (y << self.s) & self.b
        output = UntemperedMT.untemper_left(output, self.mt.s, self.mt.b)
        # untempering: y ^= (y >> self.u) & self.d
        output = UntemperedMT.untemper_right(output, self.mt.u, self.mt.d)

        return output

    def untemper_left(val: int, lshift: int, andval: int) -> int:
        mask = (1 << 32) - 1
        xval = ((val << lshift) & andval) & mask
        while xval != 0:
            val ^= xval
            xval = ((xval << lshift) & andval) & mask
        return val

    def untemper_right(val: int, rshift: int, andval: int) -> int:
        mask = (1 << 32) - 1
        xval = ((val >> rshift) & andval) & mask
        while xval != 0:
            val ^= xval
            xval = ((xval >> rshift) & andval) & mask
        return val


mt = MT()
mt.seed_buffer(15332)
outputs = [mt.extract_number() for _ in range(mt.n)]
umt = UntemperedMT()
cloned_mt = umt.clone_mt(outputs)
if cloned_mt.extract_number() == mt.extract_number():
    print("SUCCESS!")
else:
    print("Failed :(")
