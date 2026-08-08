#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include <gmpxx.h>

namespace cryptolab::rsa_diy {

inline constexpr std::uint64_t default_public_exponent = 65'537;
inline constexpr std::size_t default_modulus_bits = 4'096;

class KeyPair {
public:
  explicit KeyPair(std::uint64_t e = default_public_exponent,
                   std::size_t modulus_bits = default_modulus_bits);

  [[nodiscard]] std::pair<std::uint64_t, mpz_class> public_key() const;
  [[nodiscard]] std::pair<mpz_class, mpz_class> private_key() const;
  [[nodiscard]] mpz_class encrypt(std::uint64_t plaintext) const;
  [[nodiscard]] std::uint64_t decrypt(const mpz_class &ciphertext) const;

private:
  std::uint64_t e_;
  mpz_class modulus_;
  mpz_class d_;
};

} // namespace cryptolab::rsa_diy
