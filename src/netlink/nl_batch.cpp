#include "nl_batch.h"
#include "constants.h"
#include "nl_socket.h"

#include <atomic>
#include <ctime>
#include <unistd.h>

static uint32_t alloc_seq_block() {
    static std::atomic<uint32_t> counter{static_cast<uint32_t>(time(nullptr))};
    return counter.fetch_add(nft::SEQ_BLOCK_SIZE);
}

NlBatch::NlBatch() : NlBatch([]() -> size_t {
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    return static_cast<size_t>(ps) * nft::DEFAULT_BUF_PAGES;
}()) {}

NlBatch::NlBatch(size_t buf_size)
    : buf_(std::make_unique<char[]>(buf_size)),
      batch_(nullptr),
      seq_(0) {
    batch_ = mnl_nlmsg_batch_start(buf_.get(), buf_size);
    if (!batch_)
        return;

    seq_ = alloc_seq_block();
    nftnl_batch_begin(static_cast<char*>(mnl_nlmsg_batch_current(batch_)), seq_++);
    mnl_nlmsg_batch_next(batch_);
}

NlBatch::~NlBatch() {
    if (batch_)
        mnl_nlmsg_batch_stop(batch_);
}

bool NlBatch::is_valid() const {
    return batch_ != nullptr;
}

struct nlmsghdr* NlBatch::add_msg(uint16_t type, uint16_t family, uint16_t flags) {
    if (!batch_) return nullptr;

    return nftnl_nlmsg_build_hdr(
        static_cast<char*>(mnl_nlmsg_batch_current(batch_)),
        type,
        family,
        flags,
        seq_++
    );
}

bool NlBatch::advance() {
    if (!batch_) return false;
    return mnl_nlmsg_batch_next(batch_);
}

NlResult NlBatch::execute(NlSocket& sock, bool ignore_enoent) {
    if (!batch_)
        return {false, "batch not initialized"};

    nftnl_batch_end(static_cast<char*>(mnl_nlmsg_batch_current(batch_)), seq_++);
    mnl_nlmsg_batch_next(batch_);

    return sock.send_batch(batch_, ignore_enoent);
}
