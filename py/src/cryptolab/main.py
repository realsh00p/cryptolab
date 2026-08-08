import logging
import sys
from time import perf_counter

from cryptolab import rsa_diy, rsa_native


def run_diy() -> bool:
    """Run the handwritten RSA demonstration."""
    alice = rsa_diy.KeyPair()
    logging.debug("DIY Alice's public key: %s", alice.public_key())

    bob = rsa_diy.KeyPair()
    logging.debug("DIY Bob's public key: %s", bob.public_key())

    for_alice = 123456789
    ciphertext = alice.encrypt(for_alice)
    plaintext = alice.decrypt(ciphertext)
    if plaintext != for_alice:
        logging.error(
            "DIY error: decrypted plaintext does not match original plaintext."
        )
        return False

    logging.debug("DIY ciphertext: %s", ciphertext)
    logging.info("DIY decrypted plaintext: %s", plaintext)

    for_bob = 987654321
    ciphertext = bob.encrypt(for_bob)
    plaintext = bob.decrypt(ciphertext)
    if plaintext != for_bob:
        logging.error(
            "DIY error: decrypted plaintext does not match original plaintext."
        )
        return False

    logging.debug("DIY ciphertext: %s", ciphertext)
    logging.info("DIY decrypted plaintext: %s", plaintext)
    return True


def run_native() -> bool:
    """Run the native-backed RSA demonstration with OAEP padding."""
    alice = rsa_native.KeyPair()
    logging.debug("Native Alice's public key: %s", alice.public_key())

    bob = rsa_native.KeyPair()
    logging.debug("Native Bob's public key: %s", bob.public_key())

    for_alice = 123456789
    ciphertext = alice.encrypt(for_alice)
    plaintext = alice.decrypt(ciphertext)
    if plaintext != for_alice:
        logging.error(
            "Native error: decrypted plaintext does not match original plaintext."
        )
        return False

    if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.debug("Native ciphertext: %s", ciphertext.hex())
    logging.info("Native decrypted plaintext: %s", plaintext)

    for_bob = 987654321
    ciphertext = bob.encrypt(for_bob)
    plaintext = bob.decrypt(ciphertext)
    if plaintext != for_bob:
        logging.error(
            "Native error: decrypted plaintext does not match original plaintext."
        )
        return False

    if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.debug("Native ciphertext: %s", ciphertext.hex())
    logging.info("Native decrypted plaintext: %s", plaintext)
    return True


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )

    tick = perf_counter()
    ok = run_diy()
    tock = perf_counter()
    logging.info("DIY RSA elapsed: %.6f seconds", tock - tick)
    if not ok:
        return 1

    tick = perf_counter()
    ok = run_native()
    tock = perf_counter()
    logging.info("Native RSA elapsed: %.6f seconds", tock - tick)
    if not ok:
        return 1

    return 0
