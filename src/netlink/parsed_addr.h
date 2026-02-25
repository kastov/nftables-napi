#pragma once

#include <cstdint>

struct ParsedAddr {
    uint32_t family;       // NFPROTO_IPV4 or NFPROTO_IPV6
    uint8_t bytes[16];
    uint32_t len;          // 4 for IPv4, 16 for IPv6
};

namespace nft {
inline constexpr uint32_t FAMILY_IPV4 = 2;
inline constexpr uint32_t FAMILY_IPV6 = 10;
} // namespace nft
