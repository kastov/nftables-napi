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

// Destination address offsets
inline constexpr uint32_t IPV4_DST_OFFSET = 16;
inline constexpr uint32_t IPV6_DST_OFFSET = 24;

// Chain priority
inline constexpr int32_t CHAIN_PRIORITY = -10;

// Bulk operation parameters
// Conservative chunk size for bulk set element operations
inline constexpr uint32_t BULK_CHUNK_SIZE = 200;

// Sequence number block size allocated per batch
inline constexpr uint32_t SEQ_BLOCK_SIZE = 256;

// Number of pages for default batch buffer (pagesize * 32 ≈ 128KB)
inline constexpr uint32_t DEFAULT_BUF_PAGES = 32;

// Output chain
inline constexpr const char* CHAIN_OUTPUT = "output";

// Transport header dport offset (bytes from transport header base)
inline constexpr uint32_t TRANSPORT_DPORT_OFFSET = 2;
inline constexpr uint32_t TRANSPORT_DPORT_LEN = 2;

// Concatenated type: concat_subtype_add(inet_proto, inet_service)
// nft CLI builds concat types with LAST subtype in low bits:
// concat_subtype_add(type, subtype) = type << TYPE_BITS | subtype
// For (inet_proto=12 . inet_service=13): 12 << 6 | 13 = 781
inline constexpr uint32_t DATATYPE_PROTO_SERVICE = (12 << 6 | 13);
inline constexpr uint32_t PROTO_SERVICE_KEY_LEN = 8;

// Byte offsets within the 8-byte concatenated (proto . port) key
// Layout: [proto:1][pad:3][port_hi:1][port_lo:1][pad:2]
inline constexpr uint32_t PORT_KEY_PROTO_OFFSET = 0;
inline constexpr uint32_t PORT_KEY_PORT_HI_OFFSET = 4;
inline constexpr uint32_t PORT_KEY_PORT_LO_OFFSET = 5;

// L4 protocol numbers
inline constexpr uint8_t PROTO_TCP = 6;
inline constexpr uint8_t PROTO_UDP = 17;

// Named counter
inline constexpr const char* COUNTER_NAME = "processed";

} // namespace nft
