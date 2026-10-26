#pragma once

#include "mtdd/protocol.hpp"

#include <array>
#include <cstdint>

namespace mtdd::detail {

inline std::uint32_t random_u32(const protocol::RandomFn& random) {
    std::array<std::uint8_t, 4> bytes{};
    random(bytes);
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8) |
           (static_cast<std::uint32_t>(bytes[2]) << 16) |
           (static_cast<std::uint32_t>(bytes[3]) << 24);
}

} // namespace mtdd::detail
