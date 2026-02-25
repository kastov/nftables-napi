#pragma once

extern "C" {
#include <libmnl/libmnl.h>
#include <libnftnl/batch.h>
#include <libnftnl/common.h>
}

#include <cstdint>
#include <memory>
#include <string>

#include "nl_result.h"

class NlSocket;

class NlBatch {
public:
    NlBatch();
    explicit NlBatch(size_t buf_size);
    ~NlBatch();

    NlBatch(const NlBatch&) = delete;
    NlBatch& operator=(const NlBatch&) = delete;
    NlBatch(NlBatch&&) = delete;
    NlBatch& operator=(NlBatch&&) = delete;

    bool is_valid() const;
    struct nlmsghdr* add_msg(uint16_t type, uint16_t family, uint16_t flags);
    bool advance();
    NlResult execute(NlSocket& sock, bool ignore_enoent = false);

private:
    std::unique_ptr<char[]> buf_;
    size_t buf_size_;
    struct mnl_nlmsg_batch* batch_;
    uint32_t seq_;
};
