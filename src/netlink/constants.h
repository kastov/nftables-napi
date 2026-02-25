#pragma once

#include <cstdint>

namespace nft {

// Table and set names
inline constexpr const char* TABLE_V4 = "remnawave";
inline constexpr const char* TABLE_V6 = "remnawave6";
inline constexpr const char* SET_V4 = "blacklist";
inline constexpr const char* SET_V6 = "blacklist6";
inline constexpr const char* LOG_PREFIX = "remnawave_tb: ";

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

// Reject parameters
// NFT_REJECT_ICMP_UNREACH = 0 from linux/netfilter/nf_tables.h
inline constexpr uint32_t REJECT_TYPE_ICMP_UNREACH = 0;
// NFT_REJECT_TCP_RST = 1 from linux/netfilter/nf_tables.h
inline constexpr uint32_t REJECT_TYPE_TCP_RST = 1;
// ICMP port unreachable for IPv4 reject
inline constexpr uint32_t REJECT_CODE_V4 = 3;
// ICMPv6 admin prohibited for IPv6 reject
inline constexpr uint32_t REJECT_CODE_V6 = 1;

// Chain priority
inline constexpr int32_t CHAIN_PRIORITY = -10;

// Bulk operation parameters
// Conservative chunk size for bulk set element operations
inline constexpr uint32_t BULK_CHUNK_SIZE = 200;

// Sequence number block size allocated per batch
inline constexpr uint32_t SEQ_BLOCK_SIZE = 256;

// Number of pages for default batch buffer (pagesize * 32 ≈ 128KB)
inline constexpr uint32_t DEFAULT_BUF_PAGES = 32;

enum class FirewallStrategy : uint8_t {
    Drop = 0,
    Reject = 1,
    TcpReset = 2,
};

} // namespace nft
