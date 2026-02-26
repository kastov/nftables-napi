#pragma once

#include "operation.h"
#include "nft_config.h"
#include "parsed_addr.h"
#include <memory>
#include <vector>

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
