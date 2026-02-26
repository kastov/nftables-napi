#include "set_ops.h"
#include "nftnl_raii.h"
#include "nl_batch.h"
#include "nl_socket.h"
#include "constants.h"
#include "nft_config.h"

extern "C" {
#include <libnftnl/set.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
}

#include <algorithm>

static_assert(nft::FAMILY_IPV4 == NFPROTO_IPV4, "nft::FAMILY_IPV4 must match NFPROTO_IPV4");
static_assert(nft::FAMILY_IPV6 == NFPROTO_IPV6, "nft::FAMILY_IPV6 must match NFPROTO_IPV6");

enum class SetElemAction { Add, Del };

static NlResult bulk_set_elem_op(
    const std::vector<ParsedAddr>& addrs,
    NlSocket& sock,
    SetElemAction action,
    const nft::NftConfig& cfg,
    size_t set_idx,
    uint64_t timeout_ms = 0)
{
    std::vector<const ParsedAddr*> v4, v6;
    for (const auto& a : addrs) {
        if (a.family == NFPROTO_IPV4) v4.push_back(&a);
        else v6.push_back(&a);
    }

    const uint16_t msg_type = (action == SetElemAction::Add)
        ? NFT_MSG_NEWSETELEM : NFT_MSG_DELSETELEM;
    const uint16_t flags = (action == SetElemAction::Add)
        ? (NLM_F_CREATE | NLM_F_ACK) : NLM_F_ACK;
    const bool ignore_enoent = (action == SetElemAction::Del);

    const auto& sd = cfg.sets[set_idx];

    auto process = [&](uint32_t family, const std::vector<const ParsedAddr*>& family_addrs) -> NlResult {
        if (family_addrs.empty()) return {true, ""};

        const char* table = (family == NFPROTO_IPV4)
            ? cfg.table_v4.c_str() : cfg.table_v6.c_str();
        const char* set_name = (family == NFPROTO_IPV4)
            ? sd.name.c_str() : sd.name_v6.c_str();
        uint32_t key_type = (family == NFPROTO_IPV4) ? nft::DATATYPE_IPADDR : nft::DATATYPE_IP6ADDR;
        uint32_t key_len = (family == NFPROTO_IPV4) ? nft::IPV4_ADDR_LEN : nft::IPV6_ADDR_LEN;

        for (size_t offset = 0; offset < family_addrs.size(); offset += nft::BULK_CHUNK_SIZE) {
            size_t end = std::min(offset + static_cast<size_t>(nft::BULK_CHUNK_SIZE), family_addrs.size());

            auto s = nft::make_set();
            if (!s) return {false, "nftnl_set_alloc failed"};

            nftnl_set_set_str(s.get(), NFTNL_SET_TABLE, table);
            nftnl_set_set_str(s.get(), NFTNL_SET_NAME, set_name);
            nftnl_set_set_u32(s.get(), NFTNL_SET_FAMILY, family);
            nftnl_set_set_u32(s.get(), NFTNL_SET_KEY_TYPE, key_type);
            nftnl_set_set_u32(s.get(), NFTNL_SET_KEY_LEN, key_len);

            for (size_t i = offset; i < end; ++i) {
                auto* e = nftnl_set_elem_alloc();
                if (!e) return {false, "nftnl_set_elem_alloc failed"};
                nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, family_addrs[i]->bytes, family_addrs[i]->len);
                if (timeout_ms > 0) {
                    nftnl_set_elem_set_u64(e, NFTNL_SET_ELEM_TIMEOUT, timeout_ms);
                }
                nftnl_set_elem_add(s.get(), e);
            }

            NlBatch batch;
            if (!batch.is_valid()) return {false, "failed to allocate batch"};

            auto* nlh = batch.add_msg(msg_type, family, flags);
            if (!nlh) return {false, "failed to add message to batch"};
            nftnl_set_elems_nlmsg_build_payload(nlh, s.get());

            if (!batch.advance()) return {false, "batch buffer full"};

            NlResult res = batch.execute(sock, ignore_enoent);
            if (!res.success) return res;
        }
        return {true, ""};
    };

    NlResult res = process(NFPROTO_IPV4, v4);
    if (!res.success) return res;
    return process(NFPROTO_IPV6, v6);
}

BulkAddSetElemOp::BulkAddSetElemOp(std::vector<ParsedAddr> addrs, uint64_t timeout_ms,
                                   std::shared_ptr<const nft::NftConfig> config, size_t set_idx)
    : addrs_(std::move(addrs)), timeout_ms_(timeout_ms),
      cfg_(std::move(config)), set_idx_(set_idx) {}

NlResult BulkAddSetElemOp::execute(NlSocket& sock) {
    return bulk_set_elem_op(addrs_, sock, SetElemAction::Add, *cfg_, set_idx_, timeout_ms_);
}

BulkDelSetElemOp::BulkDelSetElemOp(std::vector<ParsedAddr> addrs,
                                   std::shared_ptr<const nft::NftConfig> config, size_t set_idx)
    : addrs_(std::move(addrs)), cfg_(std::move(config)), set_idx_(set_idx) {}

NlResult BulkDelSetElemOp::execute(NlSocket& sock) {
    return bulk_set_elem_op(addrs_, sock, SetElemAction::Del, *cfg_, set_idx_);
}
