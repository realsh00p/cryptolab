#include "cryptolab/rsa_diy.hpp"

#include <limits>
#include <stdexcept>
#include <vector>

#include <openssl/rand.h>

namespace cryptolab::rsa_diy {
namespace {

mpz_class from_unsigned(std::uint64_t value) {
  mpz_class result;
  mpz_import(result.get_mpz_t(), 1, 1, sizeof(value), 0, 0, &value);
  return result;
}

mpz_class generate_prime(std::size_t bits, std::uint64_t e) {
  if (bits < 2) {
    throw std::invalid_argument{"prime size must be at least 2 bits"};
  }

  std::vector<unsigned char> random_bytes((bits + 7) / 8);
  const auto exponent = from_unsigned(e);

  for (;;) {
    if (RAND_bytes(random_bytes.data(), random_bytes.size()) != 1) {
      throw std::runtime_error{"OpenSSL random-number generation failed"};
    }

    mpz_class candidate;
    mpz_import(candidate.get_mpz_t(), random_bytes.size(), 1,
               sizeof(random_bytes.front()), 1, 0, random_bytes.data());
    mpz_fdiv_r_2exp(candidate.get_mpz_t(), candidate.get_mpz_t(), bits);
    mpz_setbit(candidate.get_mpz_t(), bits - 1);
    mpz_setbit(candidate.get_mpz_t(), bits - 2);
    mpz_setbit(candidate.get_mpz_t(), 0);

    mpz_class divisor;
    const mpz_class candidate_minus_one = candidate - 1;
    mpz_gcd(divisor.get_mpz_t(), exponent.get_mpz_t(),
            candidate_minus_one.get_mpz_t());
    if (divisor != 1) {
      continue;
    }

    if (mpz_probab_prime_p(candidate.get_mpz_t(), 40) > 0) {
      return candidate;
    }
  }
}

} // namespace

KeyPair::KeyPair(std::uint64_t e, std::size_t modulus_bits) : e_{e} {
  if (e <= 1 || e % 2 == 0) {
    throw std::invalid_argument{"e must be an odd integer greater than 1"};
  }
  if (modulus_bits < 16) {
    throw std::invalid_argument{"modulus size must be at least 16 bits"};
  }

  const auto p_bits = modulus_bits / 2;
  const auto q_bits = modulus_bits - p_bits;
  const auto p = generate_prime(p_bits, e_);

  mpz_class q;
  do {
    q = generate_prime(q_bits, e_);
  } while (q == p);

  modulus_ = p * q;
  const mpz_class phi = (p - 1) * (q - 1);
  const auto exponent = from_unsigned(e_);
  if (mpz_invert(d_.get_mpz_t(), exponent.get_mpz_t(), phi.get_mpz_t()) == 0) {
    throw std::runtime_error{"public exponent is not invertible modulo phi(N)"};
  }
}

std::pair<std::uint64_t, mpz_class> KeyPair::public_key() const {
  return {e_, modulus_};
}

std::pair<mpz_class, mpz_class> KeyPair::private_key() const {
  return {d_, modulus_};
}

mpz_class KeyPair::encrypt(std::uint64_t plaintext) const {
  mpz_class ciphertext;
  const auto message = from_unsigned(plaintext);
  const auto exponent = from_unsigned(e_);
  mpz_powm(ciphertext.get_mpz_t(), message.get_mpz_t(), exponent.get_mpz_t(),
           modulus_.get_mpz_t());
  return ciphertext;
}

std::uint64_t KeyPair::decrypt(const mpz_class &ciphertext) const {
  mpz_class plaintext;
  mpz_powm(plaintext.get_mpz_t(), ciphertext.get_mpz_t(), d_.get_mpz_t(),
           modulus_.get_mpz_t());
  if (plaintext < 0 ||
      plaintext > from_unsigned(std::numeric_limits<std::uint64_t>::max())) {
    throw std::overflow_error{"decrypted plaintext does not fit in uint64_t"};
  }

  std::uint64_t result = 0;
  std::size_t count = 0;
  mpz_export(&result, &count, 1, sizeof(result), 0, 0, plaintext.get_mpz_t());
  return result;
}

} // namespace cryptolab::rsa_diy
