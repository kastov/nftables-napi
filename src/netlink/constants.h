#pragma once

#include <cstdint>

namespace nft {

// Chain names
inline constexpr const char* CHAIN_INPUT = "input";
inline constexpr const char* CHAIN_FORWARD = "forward";

// Chain type
inline constexpr const char* CHAIN_TYPE_FILTER = "filter";

// Data types
inline constexpr uint32_t DATATYPE_IPADDR = 7;
inline constexpr uint32_t DATATYPE_IP6ADDR = 8;

// Network header offsets and address lengths
// Offset of source address in IPv4 header (bytes)
inline constexpr uint32_t IPV4_SRC_OFFSET = 12;
// Offset of source address in IPv6 header (bytes)
inline constexpr uint32_t IPV6_SRC_OFFSET = 8;
inline constexpr uint32_t IPV4_ADDR_LEN = 4;
inline constexpr uint32_t IPV6_ADDR_LEN = 16;

// Chain priority
inline constexpr int32_t CHAIN_PRIORITY = -10;

// Bulk operation parameters
// Conservative chunk size for bulk set element operations
inline constexpr uint32_t BULK_CHUNK_SIZE = 200;

// Sequence number block size allocated per batch
inline constexpr uint32_t SEQ_BLOCK_SIZE = 256;

// Number of pages for default batch buffer (pagesize * 32 ≈ 128KB)
inline constexpr uint32_t DEFAULT_BUF_PAGES = 32;

} // namespace nft
