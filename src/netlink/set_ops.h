#pragma once

#include "operation.h"
#include "nft_config.h"
#include "parsed_addr.h"
#include <cstdint>
#include <memory>
#include <vector>

// One-shot Op: execute() consumes addrs_ via move; do not call twice.
class BulkAddSetElemOp final : public NlOperation {
public:
    BulkAddSetElemOp(std::vector<ParsedAddr> addrs, uint64_t timeout_ms,
                     std::shared_ptr<const nft::NftConfig> config, size_t set_idx);
    NlResult execute(NlSocket& sock) override;

private:
    std::vector<ParsedAddr> addrs_;
    uint64_t timeout_ms_;
    std::shared_ptr<const nft::NftConfig> cfg_;
    size_t set_idx_;
};

class BulkDelSetElemOp final : public NlOperation {
public:
    BulkDelSetElemOp(std::vector<ParsedAddr> addrs,
                     std::shared_ptr<const nft::NftConfig> config, size_t set_idx);
    NlResult execute(NlSocket& sock) override;

private:
    std::vector<ParsedAddr> addrs_;
    std::shared_ptr<const nft::NftConfig> cfg_;
    size_t set_idx_;
};

struct PortElem {
    uint8_t proto;   // nft::PROTO_TCP or nft::PROTO_UDP
    uint16_t port;
};

// One-shot Op: execute() consumes elems_ via move; do not call twice.
class BulkAddPortElemOp final : public NlOperation {
public:
    BulkAddPortElemOp(std::vector<PortElem> elems, uint64_t timeout_ms,
                      std::shared_ptr<const nft::NftConfig> config, size_t set_idx);
    NlResult execute(NlSocket& sock) override;

private:
    std::vector<PortElem> elems_;
    uint64_t timeout_ms_;
    std::shared_ptr<const nft::NftConfig> cfg_;
    size_t set_idx_;
};

class BulkDelPortElemOp final : public NlOperation {
public:
    BulkDelPortElemOp(std::vector<PortElem> elems,
                      std::shared_ptr<const nft::NftConfig> config, size_t set_idx);
    NlResult execute(NlSocket& sock) override;

private:
    std::vector<PortElem> elems_;
    std::shared_ptr<const nft::NftConfig> cfg_;
    size_t set_idx_;
};
