#!/usr/bin/python3
from random import randint
import time


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


def get_seeded_number() -> int:
    mt = MT()
    # sleep for some random interval
    delay = randint(40, 1000)
    time.sleep(delay)
    timestamp = int(time.time())
    # seed RNG with timestamp
    mt.seed_buffer(timestamp)
    random_number = mt.extract_number()
    delay = randint(40, 1000)
    time.sleep(delay)
    return random_number


target = get_seeded_number()
current_timestamp = int(time.time())
mt = MT()
mt.seed_buffer(current_timestamp)
current_val = mt.extract_number()
while target != current_val:
    current_timestamp -= 1
    mt.seed_buffer(current_timestamp)
    current_val = mt.extract_number()
print("Found timestamp: " + str(current_timestamp))
