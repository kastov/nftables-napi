#include "table_ops.h"
#include "nftnl_raii.h"
#include "nl_batch.h"
#include "nl_socket.h"
#include "constants.h"
#include "nft_config.h"

extern "C" {
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/set.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
}

using namespace nft;

static bool add_table(NlBatch& batch, uint32_t family, const char* name,
                      uint16_t msg_type, uint16_t extra_flags) {
    auto t = nft::make_table();
    if (!t) return false;
    nftnl_table_set_u32(t.get(), NFTNL_TABLE_FAMILY, family);
    nftnl_table_set_str(t.get(), NFTNL_TABLE_NAME, name);
    struct nlmsghdr* nlh = batch.add_msg(msg_type, family, NLM_F_ACK | extra_flags);
    if (!nlh) return false;
    nftnl_table_nlmsg_build_payload(nlh, t.get());
    return batch.advance();
}

static bool add_chain(NlBatch& batch, uint32_t family, const char* table,
                      const char* name, uint32_t hooknum) {
    auto c = nft::make_chain();
    if (!c) return false;
    nftnl_chain_set_str(c.get(), NFTNL_CHAIN_TABLE, table);
    nftnl_chain_set_str(c.get(), NFTNL_CHAIN_NAME, name);
    nftnl_chain_set_u32(c.get(), NFTNL_CHAIN_HOOKNUM, hooknum);
    nftnl_chain_set_s32(c.get(), NFTNL_CHAIN_PRIO, CHAIN_PRIORITY);
    nftnl_chain_set_u32(c.get(), NFTNL_CHAIN_POLICY, NF_ACCEPT);
    nftnl_chain_set_str(c.get(), NFTNL_CHAIN_TYPE, CHAIN_TYPE_FILTER);
    struct nlmsghdr* nlh = batch.add_msg(NFT_MSG_NEWCHAIN, family, NLM_F_CREATE | NLM_F_ACK);
    if (!nlh) return false;
    nftnl_chain_nlmsg_build_payload(nlh, c.get());
    return batch.advance();
}

static bool add_set(NlBatch& batch, uint32_t family, const char* table,
                    const char* name, uint32_t key_type, uint32_t key_len,
                    uint32_t set_id) {
    auto s = nft::make_set();
    if (!s) return false;
    nftnl_set_set_str(s.get(), NFTNL_SET_TABLE, table);
    nftnl_set_set_str(s.get(), NFTNL_SET_NAME, name);
    nftnl_set_set_u32(s.get(), NFTNL_SET_FAMILY, family);
    nftnl_set_set_u32(s.get(), NFTNL_SET_KEY_TYPE, key_type);
    nftnl_set_set_u32(s.get(), NFTNL_SET_KEY_LEN, key_len);
    nftnl_set_set_u32(s.get(), NFTNL_SET_FLAGS, NFT_SET_TIMEOUT);
    nftnl_set_set_u32(s.get(), NFTNL_SET_ID, set_id);
    struct nlmsghdr* nlh = batch.add_msg(NFT_MSG_NEWSET, family, NLM_F_CREATE | NLM_F_ACK);
    if (!nlh) return false;
    nftnl_set_nlmsg_build_payload(nlh, s.get());
    return batch.advance();
}

static bool add_expr_payload(struct nftnl_rule* r, uint32_t base, uint32_t dreg,
                             uint32_t offset, uint32_t len) {
    struct nftnl_expr* e = nftnl_expr_alloc("payload");
    if (!e) return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);
    nftnl_rule_add_expr(r, e);
    return true;
}

static bool add_expr_lookup(struct nftnl_rule* r, const char* set_name, uint32_t sreg) {
    struct nftnl_expr* e = nftnl_expr_alloc("lookup");
    if (!e) return false;
    nftnl_expr_set_str(e, NFTNL_EXPR_LOOKUP_SET, set_name);
    nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SREG, sreg);
    nftnl_rule_add_expr(r, e);
    return true;
}

static bool add_expr_log(struct nftnl_rule* r, const char* prefix) {
    struct nftnl_expr* e = nftnl_expr_alloc("log");
    if (!e) return false;
    nftnl_expr_set_str(e, NFTNL_EXPR_LOG_PREFIX, prefix);
    nftnl_rule_add_expr(r, e);
    return true;
}

static bool add_expr_drop(struct nftnl_rule* r) {
    struct nftnl_expr* e = nftnl_expr_alloc("immediate");
    if (!e) return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, NF_DROP);
    nftnl_rule_add_expr(r, e);
    return true;
}

// Helper: creates a rule with table/chain/family metadata, calls build_exprs
// to populate expressions, then adds to batch. Returns false on any failure.
template<typename F>
static bool add_rule_with(NlBatch& batch, uint32_t family, const char* table,
                          const char* chain, F build_exprs) {
    auto r = nft::make_rule();
    if (!r) return false;
    nftnl_rule_set_str(r.get(), NFTNL_RULE_TABLE, table);
    nftnl_rule_set_str(r.get(), NFTNL_RULE_CHAIN, chain);
    nftnl_rule_set_u32(r.get(), NFTNL_RULE_FAMILY, family);

    if (!build_exprs(r.get())) return false;

    struct nlmsghdr* nlh = batch.add_msg(NFT_MSG_NEWRULE, family,
                                          NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK);
    if (!nlh) return false;
    nftnl_rule_nlmsg_build_payload(nlh, r.get());
    return batch.advance();
}

static bool add_rule(NlBatch& batch, uint32_t family, const char* table,
                     const char* chain, const char* set_name,
                     uint32_t payload_offset, uint32_t addr_len,
                     const char* log_prefix) {
    return add_rule_with(batch, family, table, chain, [&](nftnl_rule* r) {
        return add_expr_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, payload_offset, addr_len)
            && add_expr_lookup(r, set_name, NFT_REG_1)
            && add_expr_log(r, log_prefix)
            && add_expr_drop(r);
    });
}

CreateTableOp::CreateTableOp(std::shared_ptr<const nft::NftConfig> config)
    : cfg_(std::move(config)) {}

NlResult CreateTableOp::execute(NlSocket& sock) {
    {
        NlBatch batch;
        if (!batch.is_valid())
            return {false, "failed to allocate batch"};
        if (!add_table(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), NFT_MSG_DELTABLE, 0)
            || !add_table(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), NFT_MSG_DELTABLE, 0))
            return {false, "failed to build delete-tables batch"};
        NlResult res = batch.execute(sock, true);
        if (!res.success) return res;
    }

    NlBatch batch;
    if (!batch.is_valid())
        return {false, "failed to allocate batch"};

    uint32_t sid = 0;

    if (!add_table(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), NFT_MSG_NEWTABLE, NLM_F_CREATE)
        || !add_table(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), NFT_MSG_NEWTABLE, NLM_F_CREATE))
        return {false, "failed to build tables"};

    // Blacklist sets
    if (!add_set(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), cfg_->set_v4.c_str(),
                 DATATYPE_IPADDR, IPV4_ADDR_LEN, sid++)
        || !add_set(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), cfg_->set_v6.c_str(),
                    DATATYPE_IP6ADDR, IPV6_ADDR_LEN, sid++))
        return {false, "failed to build blacklist sets"};

    // Droplist sets
    if (!add_set(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), cfg_->drop_set_v4.c_str(),
                 DATATYPE_IPADDR, IPV4_ADDR_LEN, sid++)
        || !add_set(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), cfg_->drop_set_v6.c_str(),
                    DATATYPE_IP6ADDR, IPV6_ADDR_LEN, sid++))
        return {false, "failed to build droplist sets"};

    if (!add_chain(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_INPUT, NF_INET_LOCAL_IN)
        || !add_chain(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_FORWARD, NF_INET_FORWARD)
        || !add_chain(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_INPUT, NF_INET_LOCAL_IN)
        || !add_chain(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_FORWARD, NF_INET_FORWARD))
        return {false, "failed to build chains"};

    const char* bl_lp = cfg_->blacklist_log_prefix.c_str();

    // Blacklist rules
    if (!add_rule(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_INPUT,
                  cfg_->set_v4.c_str(), IPV4_SRC_OFFSET, IPV4_ADDR_LEN, bl_lp)
        || !add_rule(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_FORWARD,
                     cfg_->set_v4.c_str(), IPV4_SRC_OFFSET, IPV4_ADDR_LEN, bl_lp)
        || !add_rule(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_INPUT,
                     cfg_->set_v6.c_str(), IPV6_SRC_OFFSET, IPV6_ADDR_LEN, bl_lp)
        || !add_rule(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_FORWARD,
                     cfg_->set_v6.c_str(), IPV6_SRC_OFFSET, IPV6_ADDR_LEN, bl_lp))
        return {false, "failed to build blacklist rules"};

    const char* dl_lp = cfg_->droplist_log_prefix.c_str();

    // Droplist rules
    if (!add_rule(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_INPUT,
                  cfg_->drop_set_v4.c_str(), IPV4_SRC_OFFSET, IPV4_ADDR_LEN, dl_lp)
        || !add_rule(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_FORWARD,
                     cfg_->drop_set_v4.c_str(), IPV4_SRC_OFFSET, IPV4_ADDR_LEN, dl_lp)
        || !add_rule(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_INPUT,
                     cfg_->drop_set_v6.c_str(), IPV6_SRC_OFFSET, IPV6_ADDR_LEN, dl_lp)
        || !add_rule(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_FORWARD,
                     cfg_->drop_set_v6.c_str(), IPV6_SRC_OFFSET, IPV6_ADDR_LEN, dl_lp))
        return {false, "failed to build droplist rules"};

    return batch.execute(sock);
}

DeleteTableOp::DeleteTableOp(std::shared_ptr<const nft::NftConfig> config)
    : cfg_(std::move(config)) {}

NlResult DeleteTableOp::execute(NlSocket& sock) {
    NlBatch batch;
    if (!batch.is_valid())
        return {false, "failed to allocate batch"};
    if (!add_table(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), NFT_MSG_DELTABLE, 0)
        || !add_table(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), NFT_MSG_DELTABLE, 0))
        return {false, "failed to build delete-tables batch"};
    return batch.execute(sock, true);
}
