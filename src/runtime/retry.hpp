#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace mtdd::detail {

constexpr std::size_t next_me_retry_attempt(std::size_t attempt) noexcept {
    return std::min<std::size_t>(attempt, 6) + 1;
}

constexpr std::chrono::milliseconds me_retry_delay(std::size_t attempt,
                                                   std::uint32_t random) noexcept {
    const auto shift = std::min<std::size_t>(attempt == 0 ? 0 : attempt - 1, 6);
    const auto base = std::min<std::int64_t>(500LL * (1LL << shift), 30000);
    // 750..1250 permille: jitter is exactly -25%..+25%, then hard-capped.
    const auto scaled = base * (750 + random % 501U) / 1000;
    return std::chrono::milliseconds(std::clamp<std::int64_t>(scaled, 100, 30000));
}

} // namespace mtdd::detail
