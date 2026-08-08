from math import gcd
from secrets import randbits

import gmpy2

DEFAULT_PUBLIC_EXPONENT = 65537
DEFAULT_MODULUS_BITS = 4096


def prime_gen(bits: int, e: int) -> int:
    if bits < 2:
        raise ValueError("bits must be at least 2")

    while True:
        # Setting the top two bits guarantees that two balanced factors produce
        # a modulus with the requested bit length. The low bit makes it odd.
        candidate = randbits(bits) | (3 << (bits - 2)) | 1

        # This factor must not prevent e from being inverted modulo phi(N).
        if gcd(e, candidate - 1) != 1:
            continue

        if gmpy2.is_prime(candidate, 40):
            return candidate


class KeyPair:
    def __init__(
        self, e: int = DEFAULT_PUBLIC_EXPONENT, modulus_bits: int = DEFAULT_MODULUS_BITS
    ) -> None:
        if e <= 1 or e % 2 == 0:
            raise ValueError("e must be an odd integer greater than 1")
        if modulus_bits < 16:
            raise ValueError("modulus_bits must be at least 16")

        self.e = e
        p_bits = modulus_bits // 2
        q_bits = modulus_bits - p_bits

        p = prime_gen(p_bits, self.e)
        while True:
            q = prime_gen(q_bits, self.e)
            if p != q:
                break

        modulus = p * q
        phi = (p - 1) * (q - 1)
        self.N = modulus
        self.d = pow(self.e, -1, phi)

    def public_key(self):
        return (self.e, self.N)

    def private_key(self):
        return (self.d, self.N)

    def encrypt(self, plaintext: int) -> int:
        return pow(plaintext, self.e, self.N)

    def decrypt(self, ciphertext: int) -> int:
        return pow(ciphertext, self.d, self.N)
