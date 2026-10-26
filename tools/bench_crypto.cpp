// Manual benchmark: link the current mtdd_protocol library and OpenSSL Crypto.
#include "mtdd/protocol.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;
namespace crypto = mtdd::protocol::crypto;
volatile std::uint64_t sink{};

// Copied pre-optimization byte-table algorithm. noinline plus a changing input
// byte and an observable checksum prevent loop hoisting/dead-code elimination.
[[gnu::noinline]] std::uint32_t old_crc(std::span<const std::uint8_t> data) {
  static const auto table = [] {
    std::array<std::uint32_t, 256> t{};
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
      t[i] = c;
    }
    return t;
  }();
  std::uint32_t c = 0xffffffffu;
  for (auto b : data) c = table[(c ^ b) & 0xff] ^ (c >> 8);
  return c ^ 0xffffffffu;
}

// Same old EVP algorithm: per-update value-initialized vector, copy and wipe.
class OldAes {
 public:
  OldAes(int mode, const std::array<std::uint8_t, 32>& key,
         const std::array<std::uint8_t, 16>& iv)
      : ctx_(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free), mode_(mode) {
    if (!ctx_ || EVP_CipherInit_ex(ctx_.get(), mode == 0 ? EVP_aes_256_ctr() : EVP_aes_256_cbc(),
                                 nullptr, key.data(), iv.data(), mode == 2 ? 0 : 1) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx_.get(), 0) != 1)
      throw std::runtime_error("old AES init");
  }
  void apply(std::span<std::uint8_t> data) {
    Bytes tmp(data.size() + 16);
    int len{};
    const int size = static_cast<int>(data.size());  // benchmark sizes <= 64 KiB
    const int ok = mode_ == 2
        ? EVP_DecryptUpdate(ctx_.get(), tmp.data(), &len, data.data(), size)
        : EVP_EncryptUpdate(ctx_.get(), tmp.data(), &len, data.data(), size);
    if (ok != 1 || len != size) throw std::runtime_error("old AES update");
    std::memcpy(data.data(), tmp.data(), data.size());
    OPENSSL_cleanse(tmp.data(), tmp.size());
  }
 private:
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_;
  int mode_{};
};

template <typename F>
double measure(std::size_t size, std::size_t iterations, F&& update) {
  Bytes storage(size + 1, 0x42);
  auto data = std::span<std::uint8_t>(storage).subspan(1);  // unaligned
  std::uint64_t checksum{};
  const auto start = std::chrono::steady_clock::now();
  for (std::size_t i = 0; i < iterations; ++i) {
    data[0] = static_cast<std::uint8_t>(i);
    checksum += update(data);
  }
  const auto elapsed = std::chrono::steady_clock::now() - start;
  sink = checksum;
  return std::chrono::duration<double, std::nano>(elapsed).count() /
         static_cast<double>(iterations);
}

template <typename Old, typename New>
void report(const char* name, std::size_t size, Old&& old_run, New&& new_run) {
  constexpr std::size_t rounds{7};
  const auto iterations = std::max<std::size_t>(2000, (16u << 20) / size);
  std::array<double, rounds> old_times{}, new_times{};
  // Warm both implementations; alternate order to reduce systematic bias.
  (void)old_run(100);
  (void)new_run(100);
  for (std::size_t r = 0; r < rounds; ++r) {
    if (r % 2 == 0) {
      old_times[r] = old_run(iterations);
      new_times[r] = new_run(iterations);
    } else {
      new_times[r] = new_run(iterations);
      old_times[r] = old_run(iterations);
    }
  }
  std::sort(old_times.begin(), old_times.end());
  std::sort(new_times.begin(), new_times.end());
  std::cout << name << ',' << size << ',' << iterations << ',' << old_times[rounds / 2]
            << ',' << new_times[rounds / 2] << ','
            << old_times[rounds / 2] / new_times[rounds / 2] << '\n';
}
}  // namespace

int main(int argc, char** argv) {
  try {
    const std::array<std::uint8_t, 32> key{};
    const std::array<std::uint8_t, 16> iv{};
    // Separate fixed-work runs for strace -c mmap/munmap comparison. Same input,
    // key and continuous CTR stream; only temporary-buffer policy differs.
    if (argc == 2) {
      const std::string_view mode(argv[1]);
      constexpr std::size_t bytes = 65536;
      constexpr std::size_t iterations = 10000;
      double elapsed{};
      if (mode == "--allocation-old") {
        OldAes aes(0, key, iv);
        elapsed = measure(bytes, iterations, [&](auto data) { aes.apply(data); return data.back(); });
      } else if (mode == "--allocation-new") {
        crypto::AesCtr aes(key, iv);
        elapsed = measure(bytes, iterations, [&](auto data) { aes.apply(data); return data.back(); });
      } else {
        return 2;
      }
      std::cout << "bytes=" << bytes << " iterations=" << iterations
                << " ns/update=" << elapsed << " checksum=" << sink << '\n';
      return 0;
    }
    if (argc != 1) return 2;
    std::cout << "compiler=" << __VERSION__ << " openssl=" << OpenSSL_version(OPENSSL_VERSION)
              << " rounds=7 median ns/update, speedup=old/new\n"
              << "operation,bytes,iterations,old_ns,new_ns,speedup\n" << std::fixed << std::setprecision(2);
    for (const std::size_t size : {64u, 256u, 1024u, 4096u, 16384u, 65536u}) {
      report("crc32", size,
             [size](auto n) { return measure(size, n, old_crc); },
             [size](auto n) { return measure(size, n, crypto::crc32); });
      for (int mode = 0; mode < 3; ++mode) {
        const auto old_run = [&](auto n) {
          OldAes aes(mode, key, iv);
          return measure(size, n, [&](auto data) { aes.apply(data); return data.back(); });
        };
        const auto new_run = [&](auto n) {
          if (mode == 0) {
            crypto::AesCtr aes(key, iv);
            return measure(size, n, [&](auto data) { aes.apply(data); return data.back(); });
          }
          crypto::AesCbc aes(key, iv);
          return measure(size, n, [&](auto data) {
            if (mode == 1) aes.encrypt(data); else aes.decrypt(data);
            return data.back();
          });
        };
        report(mode == 0 ? "ctr" : mode == 1 ? "cbc_enc" : "cbc_dec", size, old_run, new_run);
      }
    }
    std::cout << "observable_checksum=" << sink << '\n';
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
