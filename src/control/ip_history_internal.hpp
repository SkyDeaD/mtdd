// Private white-box helpers for the IP history HLL module. Tests use these to
// pin the hash, index/rank derivation and calendar math; they are not part of
// the public API.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace mtdd::control::detail {

inline constexpr size_t kHistoryRegisterCount = 1024;
inline constexpr size_t kHistoryIndexBits = 10;
inline constexpr size_t kHistoryDigestBytes = 32;
// Highest possible rank: index bits plus the all-zero remainder case.
inline constexpr uint8_t kHistoryMaxRank =
    static_cast<uint8_t>(64 - kHistoryIndexBits + 1);

using HistoryRegisters = std::array<uint8_t, kHistoryRegisterCount>;
using HistoryDigest = std::array<uint8_t, kHistoryDigestBytes>;

// One-shot keyed HMAC-SHA256. Returns false on OpenSSL failure.
bool hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data,
                 HistoryDigest& out) noexcept;

// Index from the 10 most significant digest bits (big-endian), rank from the
// leading-zero position of the remaining 54 bits (1..55).
uint32_t hll_index(const HistoryDigest& digest) noexcept;
uint8_t hll_rank(const HistoryDigest& digest) noexcept;

// Standard HLL estimate with linear counting for small cardinalities.
double hll_estimate(const HistoryRegisters& registers) noexcept;

struct CalendarStarts {
  int64_t hour{};
  int64_t day{};
  int64_t week{};  // ISO week: Monday 00:00 UTC
};

CalendarStarts calendar_starts(int64_t unix_seconds) noexcept;

}  // namespace mtdd::control::detail
