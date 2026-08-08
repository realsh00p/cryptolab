#include "cryptolab/rsa_native.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace cryptolab::rsa_native {
namespace {

[[noreturn]] void throw_openssl_error(const char *operation) {
  const auto error = ERR_get_error();
  std::array<char, 256> message{};
  ERR_error_string_n(error, message.data(), message.size());
  throw std::runtime_error{std::string{operation} + ": " + message.data()};
}

std::vector<unsigned char> encode_integer(std::uint64_t value) {
  std::array<unsigned char, sizeof(value)> encoded{};
  for (std::size_t index = 0; index < encoded.size(); ++index) {
    encoded[encoded.size() - index - 1] =
        static_cast<unsigned char>(value & 0xffU);
    value >>= 8U;
  }

  const auto first = std::find_if(encoded.begin(), encoded.end(),
                                  [](unsigned char byte) { return byte != 0; });
  if (first == encoded.end()) {
    return {0};
  }
  return {first, encoded.end()};
}

std::uint64_t decode_integer(const std::vector<unsigned char> &encoded) {
  if (encoded.size() > sizeof(std::uint64_t)) {
    throw std::overflow_error{"decrypted plaintext does not fit in uint64_t"};
  }

  std::uint64_t result = 0;
  for (const auto byte : encoded) {
    result = (result << 8U) | byte;
  }
  return result;
}

class Context {
public:
  explicit Context(EVP_PKEY *key) : value_{EVP_PKEY_CTX_new(key, nullptr)} {
    if (value_ == nullptr) {
      throw_openssl_error("EVP_PKEY_CTX_new");
    }
  }

  ~Context() { EVP_PKEY_CTX_free(value_); }
  Context(const Context &) = delete;
  Context &operator=(const Context &) = delete;

  [[nodiscard]] EVP_PKEY_CTX *get() const { return value_; }

private:
  EVP_PKEY_CTX *value_;
};

void configure_oaep(EVP_PKEY_CTX *context) {
  if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_rsa_oaep_md(context, EVP_sha256()) <= 0 ||
      EVP_PKEY_CTX_set_rsa_mgf1_md(context, EVP_sha256()) <= 0) {
    throw_openssl_error("configure RSA-OAEP");
  }
}

} // namespace

struct KeyPair::Impl {
  explicit Impl(EVP_PKEY *value) : key{value} {}
  ~Impl() { EVP_PKEY_free(key); }
  EVP_PKEY *key;
};

KeyPair::KeyPair(std::uint64_t e, std::size_t modulus_bits) {
  if (e != default_public_exponent) {
    throw std::invalid_argument{"native RSA currently supports e=65537"};
  }
  if (modulus_bits < 1'024) {
    throw std::invalid_argument{
        "native RSA modulus must be at least 1024 bits"};
  }

  auto *generated = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", modulus_bits);
  if (generated == nullptr) {
    throw_openssl_error("EVP_PKEY_Q_keygen");
  }
  impl_ = std::make_unique<Impl>(generated);
}

KeyPair::~KeyPair() = default;
KeyPair::KeyPair(KeyPair &&) noexcept = default;
KeyPair &KeyPair::operator=(KeyPair &&) noexcept = default;

std::pair<std::uint64_t, std::string> KeyPair::public_key() const {
  BIGNUM *modulus = nullptr;
  BIGNUM *exponent = nullptr;
  if (EVP_PKEY_get_bn_param(impl_->key, OSSL_PKEY_PARAM_RSA_N, &modulus) != 1 ||
      EVP_PKEY_get_bn_param(impl_->key, OSSL_PKEY_PARAM_RSA_E, &exponent) !=
          1) {
    BN_free(modulus);
    BN_free(exponent);
    throw_openssl_error("read RSA public key");
  }

  char *modulus_hex = BN_bn2hex(modulus);
  if (modulus_hex == nullptr) {
    BN_free(modulus);
    BN_free(exponent);
    throw_openssl_error("encode RSA modulus");
  }

  const auto exponent_value = static_cast<std::uint64_t>(BN_get_word(exponent));
  std::string encoded_modulus{modulus_hex};
  OPENSSL_free(modulus_hex);
  BN_free(modulus);
  BN_free(exponent);
  return {exponent_value, std::move(encoded_modulus)};
}

KeyPair::Ciphertext KeyPair::encrypt(std::uint64_t plaintext) const {
  const auto encoded = encode_integer(plaintext);
  Context context{impl_->key};
  if (EVP_PKEY_encrypt_init(context.get()) <= 0) {
    throw_openssl_error("EVP_PKEY_encrypt_init");
  }
  configure_oaep(context.get());

  std::size_t output_size = 0;
  if (EVP_PKEY_encrypt(context.get(), nullptr, &output_size, encoded.data(),
                       encoded.size()) <= 0) {
    throw_openssl_error("measure RSA ciphertext");
  }

  Ciphertext ciphertext(output_size);
  if (EVP_PKEY_encrypt(context.get(), ciphertext.data(), &output_size,
                       encoded.data(), encoded.size()) <= 0) {
    throw_openssl_error("RSA encrypt");
  }
  ciphertext.resize(output_size);
  return ciphertext;
}

std::uint64_t KeyPair::decrypt(const Ciphertext &ciphertext) const {
  Context context{impl_->key};
  if (EVP_PKEY_decrypt_init(context.get()) <= 0) {
    throw_openssl_error("EVP_PKEY_decrypt_init");
  }
  configure_oaep(context.get());

  std::size_t output_size = 0;
  if (EVP_PKEY_decrypt(context.get(), nullptr, &output_size, ciphertext.data(),
                       ciphertext.size()) <= 0) {
    throw_openssl_error("measure RSA plaintext");
  }

  std::vector<unsigned char> encoded(output_size);
  if (EVP_PKEY_decrypt(context.get(), encoded.data(), &output_size,
                       ciphertext.data(), ciphertext.size()) <= 0) {
    throw_openssl_error("RSA decrypt");
  }
  encoded.resize(output_size);
  return decode_integer(encoded);
}

} // namespace cryptolab::rsa_native
