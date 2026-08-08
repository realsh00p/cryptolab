from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEFAULT_PUBLIC_EXPONENT = 65537
DEFAULT_MODULUS_BITS = 4096

OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class KeyPair:
    def __init__(
        self,
        e: int = DEFAULT_PUBLIC_EXPONENT,
        modulus_bits: int = DEFAULT_MODULUS_BITS,
    ) -> None:
        self._private_key = rsa.generate_private_key(
            public_exponent=e,
            key_size=modulus_bits,
        )

    def public_key(self) -> tuple[int, int]:
        numbers = self._private_key.public_key().public_numbers()
        return numbers.e, numbers.n

    def private_key(self) -> rsa.RSAPrivateKey:
        return self._private_key

    def encrypt(self, plaintext: int) -> bytes:
        encoded = _encode_integer(plaintext)
        return self._private_key.public_key().encrypt(encoded, OAEP_PADDING)

    def decrypt(self, ciphertext: bytes) -> int:
        encoded = self._private_key.decrypt(ciphertext, OAEP_PADDING)
        return int.from_bytes(encoded, byteorder="big")


def _encode_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("plaintext must be non-negative")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), byteorder="big")
