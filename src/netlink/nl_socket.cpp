#include "nl_socket.h"

extern "C" {
#include <linux/netfilter/nfnetlink.h>
}

#include <cerrno>
#include <cstring>
#include <sys/socket.h>

static constexpr size_t RECV_BUF_SIZE = 16384;

// Custom NLMSG_ERROR handler for mnl_cb_run2.
// Returns MNL_CB_OK for success ACKs and ignored ENOENT errors,
// allowing mnl_cb_run2 to continue processing all messages in buffer.
// Returns MNL_CB_ERROR for real errors.
struct BatchRecvCtx {
    bool ignore_enoent;
    bool has_error;
    int error_code;
};

static int batch_error_cb(const struct nlmsghdr* nlh, void* data) {
    auto* ctx = static_cast<BatchRecvCtx*>(data);

    if (nlh->nlmsg_len < mnl_nlmsg_size(sizeof(struct nlmsgerr))) {
        ctx->has_error = true;
        ctx->error_code = EBADMSG;
        errno = EBADMSG;
        return MNL_CB_ERROR;
    }

    auto* err = static_cast<struct nlmsgerr*>(mnl_nlmsg_get_payload(nlh));

    if (err->error == 0)
        return MNL_CB_OK; // success ACK — continue

    if (ctx->ignore_enoent && err->error == -ENOENT)
        return MNL_CB_OK; // ignored error — continue

    ctx->has_error = true;
    ctx->error_code = -err->error;
    errno = -err->error;
    return MNL_CB_ERROR;
}

NlSocket::NlSocket() : nl_(nullptr), portid_(0) {
    nl_ = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl_)
        return;

    if (mnl_socket_bind(nl_, 0, MNL_SOCKET_AUTOPID) < 0) {
        mnl_socket_close(nl_);
        nl_ = nullptr;
        return;
    }

    // Tune socket buffers for bulk batch operations.
    // Failures are non-fatal; the kernel may cap at rmem_max/wmem_max.
    static constexpr int SOCK_BUF_SIZE = 256 * 1024;
    int fd = mnl_socket_get_fd(nl_);
    // Non-fatal: kernel may reject buffer size increase
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &SOCK_BUF_SIZE, sizeof(SOCK_BUF_SIZE));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &SOCK_BUF_SIZE, sizeof(SOCK_BUF_SIZE));

    portid_ = mnl_socket_get_portid(nl_);
}

NlSocket::~NlSocket() {
    if (nl_)
        mnl_socket_close(nl_);
}

bool NlSocket::is_valid() const {
    return nl_ != nullptr;
}

NlResult NlSocket::send_batch(struct mnl_nlmsg_batch* batch, bool ignore_enoent, uint32_t base_seq) {
    ssize_t sent = mnl_socket_sendto(nl_,
                                     mnl_nlmsg_batch_head(batch),
                                     mnl_nlmsg_batch_size(batch));
    if (sent < 0)
        return {false, std::string("mnl_socket_sendto: ") + strerror(errno)};

    BatchRecvCtx ctx{ignore_enoent, false, 0};

    // Custom control callback array: override only NLMSG_ERROR (index 2).
    // Array size = NLMSG_ERROR + 1 = 3, so NLMSG_DONE (3) and others
    // fall through to default mnl handling.
    mnl_cb_t cb_ctl[NLMSG_ERROR + 1] = {};
    cb_ctl[NLMSG_ERROR] = batch_error_cb;

    int fd = mnl_socket_get_fd(nl_);
    char recv_buf[RECV_BUF_SIZE];

    // First read: blocking (kernel response should arrive promptly)
    ssize_t ret = mnl_socket_recvfrom(nl_, recv_buf, sizeof(recv_buf));
    if (ret < 0)
        return {false, std::string("mnl_socket_recvfrom: ") + strerror(errno)};
    while (ret > 0) {
        int cb_ret = mnl_cb_run2(recv_buf, static_cast<size_t>(ret), base_seq, portid_,
                                  nullptr, &ctx, cb_ctl, NLMSG_ERROR + 1);
        if (cb_ret <= 0)
            break;

        // Non-blocking read for remaining kernel responses
        do {
            ret = recv(fd, recv_buf, sizeof(recv_buf), MSG_DONTWAIT);
        } while (ret < 0 && errno == EINTR);
    }

    // Drain any leftover messages to keep socket clean for next operation
    for (;;) {
        ssize_t r = recv(fd, recv_buf, sizeof(recv_buf), MSG_DONTWAIT);
        if (r > 0) continue;
        if (r < 0 && errno == EINTR) continue;
        break;
    }

    if (ctx.has_error)
        return {false, std::string("batch error: ") + strerror(ctx.error_code)};

    return {true, ""};
}
