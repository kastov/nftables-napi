#pragma once

#include "operation.h"
#include "nft_config.h"
#include <memory>

class CreateTableOp final : public NlOperation {
public:
    explicit CreateTableOp(std::shared_ptr<const nft::NftConfig> config);
    NlResult execute(NlSocket& sock) override;

private:
    std::shared_ptr<const nft::NftConfig> cfg_;
};

class DeleteTableOp final : public NlOperation {
public:
    explicit DeleteTableOp(std::shared_ptr<const nft::NftConfig> config);
    NlResult execute(NlSocket& sock) override;

private:
    std::shared_ptr<const nft::NftConfig> cfg_;
};
