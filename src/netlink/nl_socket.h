#pragma once

extern "C" {
#include <libmnl/libmnl.h>
}

#include <cstdint>

#include "nl_result.h"

class NlSocket {
public:
    NlSocket();
    ~NlSocket();

    NlSocket(const NlSocket&) = delete;
    NlSocket& operator=(const NlSocket&) = delete;
    NlSocket(NlSocket&&) = delete;
    NlSocket& operator=(NlSocket&&) = delete;

    bool is_valid() const;

    NlResult send_batch(struct mnl_nlmsg_batch* batch, bool ignore_enoent = false);

private:
    struct mnl_socket* nl_;
    uint32_t portid_;
};
