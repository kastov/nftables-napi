#pragma once

#include "operation.h"
#include <cstdint>
#include <vector>

struct ParsedAddr {
    uint32_t family;       // NFPROTO_IPV4 or NFPROTO_IPV6
    uint8_t bytes[16];
    uint32_t len;          // 4 for IPv4, 16 for IPv6
};

class BulkAddSetElemOp final : public NlOperation {
public:
    BulkAddSetElemOp(std::vector<ParsedAddr> addrs, uint64_t timeout_ms);
    NlResult execute(NlSocket& sock) override;

private:
    std::vector<ParsedAddr> addrs_;
    uint64_t timeout_ms_;
};

class BulkDelSetElemOp final : public NlOperation {
public:
    explicit BulkDelSetElemOp(std::vector<ParsedAddr> addrs);
    NlResult execute(NlSocket& sock) override;

private:
    std::vector<ParsedAddr> addrs_;
};
