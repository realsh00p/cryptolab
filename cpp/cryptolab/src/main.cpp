#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>

#include "cryptolab/rsa_diy.hpp"
#include "cryptolab/rsa_native.hpp"

namespace {

using Clock = std::chrono::steady_clock;

bool run_diy() {
  cryptolab::rsa_diy::KeyPair alice;
  cryptolab::rsa_diy::KeyPair bob;

  constexpr std::uint64_t for_alice = 123'456'789;
  const auto alice_ciphertext = alice.encrypt(for_alice);
  const auto alice_plaintext = alice.decrypt(alice_ciphertext);
  if (alice_plaintext != for_alice) {
    std::clog << "ERROR DIY decrypted plaintext does not match\n";
    return false;
  }
  std::clog << "INFO DIY decrypted plaintext: " << alice_plaintext << '\n';

  constexpr std::uint64_t for_bob = 987'654'321;
  const auto bob_ciphertext = bob.encrypt(for_bob);
  const auto bob_plaintext = bob.decrypt(bob_ciphertext);
  if (bob_plaintext != for_bob) {
    std::clog << "ERROR DIY decrypted plaintext does not match\n";
    return false;
  }
  std::clog << "INFO DIY decrypted plaintext: " << bob_plaintext << '\n';
  return true;
}

bool run_native() {
  cryptolab::rsa_native::KeyPair alice;
  cryptolab::rsa_native::KeyPair bob;

  constexpr std::uint64_t for_alice = 123'456'789;
  const auto alice_ciphertext = alice.encrypt(for_alice);
  const auto alice_plaintext = alice.decrypt(alice_ciphertext);
  if (alice_plaintext != for_alice) {
    std::clog << "ERROR Native decrypted plaintext does not match\n";
    return false;
  }
  std::clog << "INFO Native decrypted plaintext: " << alice_plaintext << '\n';

  constexpr std::uint64_t for_bob = 987'654'321;
  const auto bob_ciphertext = bob.encrypt(for_bob);
  const auto bob_plaintext = bob.decrypt(bob_ciphertext);
  if (bob_plaintext != for_bob) {
    std::clog << "ERROR Native decrypted plaintext does not match\n";
    return false;
  }
  std::clog << "INFO Native decrypted plaintext: " << bob_plaintext << '\n';
  return true;
}

double elapsed_seconds(Clock::time_point start, Clock::time_point stop) {
  return std::chrono::duration<double>(stop - start).count();
}

} // namespace

int main() {
  try {
    std::clog << std::fixed << std::setprecision(6);

    auto tick = Clock::now();
    const auto diy_ok = run_diy();
    auto tock = Clock::now();
    std::clog << "INFO DIY RSA elapsed: " << elapsed_seconds(tick, tock)
              << " seconds\n";
    if (!diy_ok) {
      return 1;
    }

    tick = Clock::now();
    const auto native_ok = run_native();
    tock = Clock::now();
    std::clog << "INFO Native RSA elapsed: " << elapsed_seconds(tick, tock)
              << " seconds\n";
    return native_ok ? 0 : 1;
  } catch (const std::exception &error) {
    std::clog << "ERROR " << error.what() << '\n';
    return 1;
  }
}
