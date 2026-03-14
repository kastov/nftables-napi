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
#include <libnftnl/object.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
}

using namespace nft;

// ── Table helpers ────────────────────────────────────────────────────────────

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

// ── Chain helpers ────────────────────────────────────────────────────────────

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

// ── Named counter (stateful object) ─────────────────────────────────────────

static bool add_counter_obj(NlBatch& batch, uint32_t family, const char* table,
                            const char* name) {
    auto o = nft::make_obj();
    if (!o) return false;
    nftnl_obj_set_str(o.get(), NFTNL_OBJ_TABLE, table);
    nftnl_obj_set_str(o.get(), NFTNL_OBJ_NAME, name);
    nftnl_obj_set_u32(o.get(), NFTNL_OBJ_TYPE, NFT_OBJECT_COUNTER);
    struct nlmsghdr* nlh = batch.add_msg(NFT_MSG_NEWOBJ, family, NLM_F_CREATE | NLM_F_ACK);
    if (!nlh) return false;
    nftnl_obj_nlmsg_build_payload(nlh, o.get());
    return batch.advance();
}

// ── Set helpers ─────────────────────────────────────────────────────────────

static bool add_set(NlBatch& batch, uint32_t family, const char* table,
                    const char* name, uint32_t key_type, uint32_t key_len,
                    uint32_t set_id,
                    const uint32_t* concat_field_lens = nullptr,
                    size_t concat_field_bytes = 0) {
    auto s = nft::make_set();
    if (!s) return false;
    nftnl_set_set_str(s.get(), NFTNL_SET_TABLE, table);
    nftnl_set_set_str(s.get(), NFTNL_SET_NAME, name);
    nftnl_set_set_u32(s.get(), NFTNL_SET_FAMILY, family);
    nftnl_set_set_u32(s.get(), NFTNL_SET_KEY_TYPE, key_type);
    nftnl_set_set_u32(s.get(), NFTNL_SET_KEY_LEN, key_len);

    uint32_t set_flags = NFT_SET_TIMEOUT | NFT_SET_EXPR;
    if (concat_field_lens && concat_field_bytes > 0)
        set_flags |= NFT_SET_CONCAT;
    nftnl_set_set_u32(s.get(), NFTNL_SET_FLAGS, set_flags);
    nftnl_set_set_u32(s.get(), NFTNL_SET_ID, set_id);

    if (concat_field_lens && concat_field_bytes > 0) {
        nftnl_set_set_data(s.get(), NFTNL_SET_DESC_CONCAT,
                           concat_field_lens, concat_field_bytes);
    }

    // Per-element counter expression
    struct nftnl_expr* counter = nftnl_expr_alloc("counter");
    if (!counter) return false;
    nftnl_set_add_expr(s.get(), counter);  // ownership transferred

    struct nlmsghdr* nlh = batch.add_msg(NFT_MSG_NEWSET, family, NLM_F_CREATE | NLM_F_ACK);
    if (!nlh) return false;
    nftnl_set_nlmsg_build_payload(nlh, s.get());
    return batch.advance();
}

// ── Expression helpers ──────────────────────────────────────────────────────

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

static bool add_expr_counter_ref(struct nftnl_rule* r, const char* counter_name) {
    struct nftnl_expr* e = nftnl_expr_alloc("objref");
    if (!e) return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_OBJREF_IMM_TYPE, NFT_OBJECT_COUNTER);
    nftnl_expr_set_str(e, NFTNL_EXPR_OBJREF_IMM_NAME, counter_name);
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

// ── Rule builder ────────────────────────────────────────────────────────────

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

// Rule: counter name "processed" (standalone rule in chain)
static bool add_rule_counter_ref(NlBatch& batch, uint32_t family, const char* table,
                                 const char* chain) {
    return add_rule_with(batch, family, table, chain, [](nftnl_rule* r) {
        return add_expr_counter_ref(r, COUNTER_NAME);
    });
}

// InIP rule: payload(saddr) + lookup(set) + log(prefix) + counter_ref(set_name) + drop
static bool add_rule_in_ip(NlBatch& batch, uint32_t family, const char* table,
                           const char* chain, const char* set_name,
                           uint32_t payload_offset, uint32_t addr_len,
                           const char* log_prefix, const char* counter_name) {
    return add_rule_with(batch, family, table, chain, [&](nftnl_rule* r) {
        return add_expr_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, payload_offset, addr_len)
            && add_expr_lookup(r, set_name, NFT_REG_1)
            && add_expr_log(r, log_prefix)
            && add_expr_counter_ref(r, counter_name)
            && add_expr_drop(r);
    });
}

// OutIP rule: payload(daddr) + lookup(set) + counter_ref(set_name) + drop (NO log)
static bool add_rule_out_ip(NlBatch& batch, uint32_t family, const char* table,
                            const char* chain, const char* set_name,
                            uint32_t payload_offset, uint32_t addr_len,
                            const char* counter_name) {
    return add_rule_with(batch, family, table, chain, [&](nftnl_rule* r) {
        return add_expr_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, payload_offset, addr_len)
            && add_expr_lookup(r, set_name, NFT_REG_1)
            && add_expr_counter_ref(r, counter_name)
            && add_expr_drop(r);
    });
}

// OutPort rule: meta(l4proto) → REG32_00, payload(transport dport) → REG32_01,
//               lookup(concat set, REG32_00) + counter_ref + drop
static bool add_rule_out_port_concat(NlBatch& batch, uint32_t family, const char* table,
                                     const char* chain, const char* set_name,
                                     const char* counter_name) {
    return add_rule_with(batch, family, table, chain, [&](nftnl_rule* r) {
        // meta l4proto → NFT_REG32_00
        struct nftnl_expr* meta = nftnl_expr_alloc("meta");
        if (!meta) return false;
        nftnl_expr_set_u32(meta, NFTNL_EXPR_META_KEY, NFT_META_L4PROTO);
        nftnl_expr_set_u32(meta, NFTNL_EXPR_META_DREG, NFT_REG32_00);
        nftnl_rule_add_expr(r, meta);

        // payload transport dport → NFT_REG32_01
        struct nftnl_expr* pay = nftnl_expr_alloc("payload");
        if (!pay) return false;
        nftnl_expr_set_u32(pay, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
        nftnl_expr_set_u32(pay, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG32_01);
        nftnl_expr_set_u32(pay, NFTNL_EXPR_PAYLOAD_OFFSET, TRANSPORT_DPORT_OFFSET);
        nftnl_expr_set_u32(pay, NFTNL_EXPR_PAYLOAD_LEN, TRANSPORT_DPORT_LEN);
        nftnl_rule_add_expr(r, pay);

        // lookup in concatenated set starting from REG32_00
        return add_expr_lookup(r, set_name, NFT_REG32_00)
            && add_expr_counter_ref(r, counter_name)
            && add_expr_drop(r);
    });
}

// ── CreateTableOp ───────────────────────────────────────────────────────────

CreateTableOp::CreateTableOp(std::shared_ptr<const nft::NftConfig> config)
    : cfg_(std::move(config)) {}

NlResult CreateTableOp::execute(NlSocket& sock) {
    // Phase 1: Delete existing tables (idempotent)
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

    // Phase 2: Create everything
    NlBatch batch;
    if (!batch.is_valid())
        return {false, "failed to allocate batch"};

    uint32_t sid = 0;

    // Tables
    if (!add_table(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), NFT_MSG_NEWTABLE, NLM_F_CREATE)
        || !add_table(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), NFT_MSG_NEWTABLE, NLM_F_CREATE))
        return {false, "failed to build tables"};

    // Named counter: "processed" (global traffic counter)
    if (!add_counter_obj(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), COUNTER_NAME)
        || !add_counter_obj(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), COUNTER_NAME))
        return {false, "failed to build 'processed' counter"};

    // Named counters: per-set
    for (const auto& sd : cfg_->sets) {
        if (!add_counter_obj(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), sd.name.c_str())
            || !add_counter_obj(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), sd.name_v6.c_str()))
            return {false, "failed to build counter for set '" + sd.name + "'"};
    }

    // Sets
    for (const auto& sd : cfg_->sets) {
        uint32_t key_type_v4, key_type_v6, key_len_v4, key_len_v6;
        const uint32_t* concat_fields = nullptr;
        size_t concat_bytes = 0;
        static constexpr uint32_t proto_port_fields[2] = {1, 2};

        if (sd.kind == SetKind::OutPort) {
            key_type_v4 = DATATYPE_PROTO_SERVICE;
            key_type_v6 = DATATYPE_PROTO_SERVICE;
            key_len_v4 = PROTO_SERVICE_KEY_LEN;
            key_len_v6 = PROTO_SERVICE_KEY_LEN;
            concat_fields = proto_port_fields;
            concat_bytes = sizeof(proto_port_fields);
        } else {
            key_type_v4 = DATATYPE_IPADDR;
            key_type_v6 = DATATYPE_IP6ADDR;
            key_len_v4 = IPV4_ADDR_LEN;
            key_len_v6 = IPV6_ADDR_LEN;
        }
        if (!add_set(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), sd.name.c_str(),
                     key_type_v4, key_len_v4, sid++, concat_fields, concat_bytes)
            || !add_set(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), sd.name_v6.c_str(),
                        key_type_v6, key_len_v6, sid++, concat_fields, concat_bytes))
            return {false, "failed to build set '" + sd.name + "'"};
    }

    // Chains: input + forward + output
    if (!add_chain(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_INPUT, NF_INET_LOCAL_IN)
        || !add_chain(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_FORWARD, NF_INET_FORWARD)
        || !add_chain(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_OUTPUT, NF_INET_LOCAL_OUT)
        || !add_chain(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_INPUT, NF_INET_LOCAL_IN)
        || !add_chain(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_FORWARD, NF_INET_FORWARD)
        || !add_chain(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_OUTPUT, NF_INET_LOCAL_OUT))
        return {false, "failed to build chains"};

    // Rules: "counter name processed" on input + forward chains
    if (!add_rule_counter_ref(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_INPUT)
        || !add_rule_counter_ref(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_FORWARD)
        || !add_rule_counter_ref(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_INPUT)
        || !add_rule_counter_ref(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_FORWARD))
        return {false, "failed to build 'processed' counter rules"};

    // Rules per set
    for (const auto& sd : cfg_->sets) {
        const char* lp = sd.log_prefix.c_str();
        switch (sd.kind) {
        case SetKind::InIP:
            // input + forward: saddr + log + counter_ref + drop
            if (!add_rule_in_ip(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_INPUT,
                                sd.name.c_str(), IPV4_SRC_OFFSET, IPV4_ADDR_LEN, lp, sd.name.c_str())
                || !add_rule_in_ip(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_FORWARD,
                                   sd.name.c_str(), IPV4_SRC_OFFSET, IPV4_ADDR_LEN, lp, sd.name.c_str())
                || !add_rule_in_ip(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_INPUT,
                                   sd.name_v6.c_str(), IPV6_SRC_OFFSET, IPV6_ADDR_LEN, lp, sd.name_v6.c_str())
                || !add_rule_in_ip(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_FORWARD,
                                   sd.name_v6.c_str(), IPV6_SRC_OFFSET, IPV6_ADDR_LEN, lp, sd.name_v6.c_str()))
                return {false, "failed to build rules for set '" + sd.name + "'"};
            break;

        case SetKind::OutIP:
            // output: daddr + counter_ref + drop (NO log)
            if (!add_rule_out_ip(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_OUTPUT,
                                 sd.name.c_str(), IPV4_DST_OFFSET, IPV4_ADDR_LEN,
                                 sd.name.c_str())
                || !add_rule_out_ip(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_OUTPUT,
                                    sd.name_v6.c_str(), IPV6_DST_OFFSET, IPV6_ADDR_LEN,
                                    sd.name_v6.c_str()))
                return {false, "failed to build output rules for set '" + sd.name + "'"};
            break;

        case SetKind::OutPort:
            // output: single concatenated (proto . port) lookup + counter_ref + drop
            if (!add_rule_out_port_concat(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_OUTPUT,
                                          sd.name.c_str(), sd.name.c_str())
                || !add_rule_out_port_concat(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_OUTPUT,
                                             sd.name_v6.c_str(), sd.name_v6.c_str()))
                return {false, "failed to build port rules for set '" + sd.name + "'"};
            break;
        }
    }

    return batch.execute(sock);
}

// ── DeleteTableOp ───────────────────────────────────────────────────────────

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
