#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace cryptolab::rsa_native {

inline constexpr std::uint64_t default_public_exponent = 65'537;
inline constexpr std::size_t default_modulus_bits = 4'096;

class KeyPair {
public:
  using Ciphertext = std::vector<unsigned char>;

  explicit KeyPair(std::uint64_t e = default_public_exponent,
                   std::size_t modulus_bits = default_modulus_bits);
  ~KeyPair();

  KeyPair(const KeyPair &) = delete;
  KeyPair &operator=(const KeyPair &) = delete;
  KeyPair(KeyPair &&) noexcept;
  KeyPair &operator=(KeyPair &&) noexcept;

  [[nodiscard]] std::pair<std::uint64_t, std::string> public_key() const;
  [[nodiscard]] Ciphertext encrypt(std::uint64_t plaintext) const;
  [[nodiscard]] std::uint64_t decrypt(const Ciphertext &ciphertext) const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace cryptolab::rsa_native
