#pragma once

#include "constants.h"
#include "operation.h"

class CreateTableOp final : public NlOperation {
public:
    explicit CreateTableOp(nft::FirewallStrategy strategy = nft::FirewallStrategy::Reject);
    NlResult execute(NlSocket& sock) override;
private:
    nft::FirewallStrategy strategy_;
};

class DeleteTableOp final : public NlOperation {
public:
    NlResult execute(NlSocket& sock) override;
};
