#pragma once

#include <cstdint>

struct ParsedAddr {
    uint32_t family;       // nft::FAMILY_IPV4 or nft::FAMILY_IPV6 (== NFPROTO_IPV4/IPV6)
    uint8_t bytes[16];     // key (start of interval)
    uint8_t end_bytes[16]; // key_end (exclusive end of interval)
    uint32_t len;          // 4 for IPv4, 16 for IPv6
};

namespace nft {
inline constexpr uint32_t FAMILY_IPV4 = 2;
inline constexpr uint32_t FAMILY_IPV6 = 10;
} // namespace nft
