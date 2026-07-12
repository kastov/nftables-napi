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
#include <cerrno>
#include <string>

using namespace nft;


// Table helpers
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


// Chain helpers
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


// Named counter helpers
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


// Set helpers
static bool add_set(NlBatch& batch, uint32_t family, const char* table,
                    const char* name, uint32_t key_type, uint32_t key_len,
                    uint32_t set_id, bool interval = false,
                    const uint8_t* concat_field_lens = nullptr,
                    size_t concat_field_count = 0,
                    bool per_element_counters = true,
                    bool use_concat_flag = true) {
    auto s = nft::make_set();
    if (!s) return false;
    nftnl_set_set_str(s.get(), NFTNL_SET_TABLE, table);
    nftnl_set_set_str(s.get(), NFTNL_SET_NAME, name);
    nftnl_set_set_u32(s.get(), NFTNL_SET_FAMILY, family);
    nftnl_set_set_u32(s.get(), NFTNL_SET_KEY_TYPE, key_type);
    nftnl_set_set_u32(s.get(), NFTNL_SET_KEY_LEN, key_len);

    uint32_t set_flags = NFT_SET_TIMEOUT;
    if (per_element_counters)
        set_flags |= NFT_SET_EXPR;
    if (interval)
        set_flags |= NFT_SET_INTERVAL;
    if (concat_field_lens && concat_field_count > 0 && use_concat_flag)
        set_flags |= NFT_SET_CONCAT;
    nftnl_set_set_u32(s.get(), NFTNL_SET_FLAGS, set_flags);
    // set_id 0 = omit (transaction-local IDs only needed for same-batch rule refs)
    if (set_id != 0)
        nftnl_set_set_u32(s.get(), NFTNL_SET_ID, set_id);

    if (concat_field_lens && concat_field_count > 0) {
        nftnl_set_set_data(s.get(), NFTNL_SET_DESC_CONCAT,
                           concat_field_lens, concat_field_count);
    }

    if (per_element_counters) {
        // Per-element counter expression
        struct nftnl_expr* counter = nftnl_expr_alloc("counter");
        if (!counter) return false;
        nftnl_set_add_expr(s.get(), counter);  // ownership transferred
    }

    struct nlmsghdr* nlh = batch.add_msg(NFT_MSG_NEWSET, family, NLM_F_CREATE | NLM_F_ACK);
    if (!nlh) return false;
    nftnl_set_nlmsg_build_payload(nlh, s.get());
    return batch.advance();
}


// Expression helpers
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

static bool add_expr_lookup(struct nftnl_rule* r, const char* set_name,
                            uint32_t set_id, uint32_t sreg) {
    struct nftnl_expr* e = nftnl_expr_alloc("lookup");
    if (!e) return false;
    nftnl_expr_set_str(e, NFTNL_EXPR_LOOKUP_SET, set_name);
    // set_id 0 means "unset"; resolve committed sets by name only.
    // Non-zero IDs are only useful for same-batch set references.
    if (set_id != 0)
        nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SET_ID, set_id);
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


// Rule builder
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
                           uint32_t set_id,
                           uint32_t payload_offset, uint32_t addr_len,
                           const char* log_prefix, const char* counter_name) {
    return add_rule_with(batch, family, table, chain, [&](nftnl_rule* r) {
        return add_expr_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, payload_offset, addr_len)
            && add_expr_lookup(r, set_name, set_id, NFT_REG_1)
            && add_expr_log(r, log_prefix)
            && add_expr_counter_ref(r, counter_name)
            && add_expr_drop(r);
    });
}

// OutIP rule: payload(daddr) + lookup(set) + counter_ref(set_name) + drop (NO log)
static bool add_rule_out_ip(NlBatch& batch, uint32_t family, const char* table,
                            const char* chain, const char* set_name,
                            uint32_t set_id,
                            uint32_t payload_offset, uint32_t addr_len,
                            const char* counter_name) {
    return add_rule_with(batch, family, table, chain, [&](nftnl_rule* r) {
        return add_expr_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, payload_offset, addr_len)
            && add_expr_lookup(r, set_name, set_id, NFT_REG_1)
            && add_expr_counter_ref(r, counter_name)
            && add_expr_drop(r);
    });
}

// Output-port rule: protocol/port lookup + counter + drop.
static bool add_rule_out_port_concat(NlBatch& batch, uint32_t family, const char* table,
                                     const char* chain, const char* set_name,
                                     uint32_t set_id,
                                     const char* counter_name) {
    return add_rule_with(batch, family, table, chain, [&](nftnl_rule* r) {
        struct nftnl_expr* meta = nftnl_expr_alloc("meta");
        if (!meta) return false;
        nftnl_expr_set_u32(meta, NFTNL_EXPR_META_KEY, NFT_META_L4PROTO);
        nftnl_expr_set_u32(meta, NFTNL_EXPR_META_DREG, NFT_REG32_00);
        nftnl_rule_add_expr(r, meta);

        struct nftnl_expr* pay = nftnl_expr_alloc("payload");
        if (!pay) return false;
        nftnl_expr_set_u32(pay, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
        nftnl_expr_set_u32(pay, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG32_01);
        nftnl_expr_set_u32(pay, NFTNL_EXPR_PAYLOAD_OFFSET, TRANSPORT_DPORT_OFFSET);
        nftnl_expr_set_u32(pay, NFTNL_EXPR_PAYLOAD_LEN, TRANSPORT_DPORT_LEN);
        nftnl_rule_add_expr(r, pay);

        // lookup in concatenated set starting from REG32_00
        return add_expr_lookup(r, set_name, set_id, NFT_REG32_00)
            && add_expr_counter_ref(r, counter_name)
            && add_expr_drop(r);
    });
}


// CreateTableOp
CreateTableOp::CreateTableOp(std::shared_ptr<const nft::NftConfig> config)
    : cfg_(std::move(config)) {}

// Helper: describe key layout for one SetDef on one family.
static void set_key_params(const SetDef& sd, bool ipv6,
                           uint32_t& key_type, uint32_t& key_len,
                           const uint8_t*& concat_fields, size_t& concat_count) {
    static constexpr uint8_t proto_port_fields[2] = {1, 2};
    if (sd.kind == SetKind::OutPort) {
        key_type = DATATYPE_PROTO_SERVICE;
        key_len = PROTO_SERVICE_KEY_LEN;
        concat_fields = proto_port_fields;
        concat_count = sizeof(proto_port_fields);
    } else if (ipv6) {
        key_type = DATATYPE_IP6ADDR;
        key_len = IPV6_ADDR_LEN;
        concat_fields = nullptr;
        concat_count = 0;
    } else {
        key_type = DATATYPE_IPADDR;
        key_len = IPV4_ADDR_LEN;
        concat_fields = nullptr;
        concat_count = 0;
    }
}

// Commit a single NEWSET in its own netlink batch.
// RouterOS quirks observed in the field:
//  - multi-set batches: later sets / rule lookups can fail
//  - interval address sets: require non-zero NFTA_SET_ID
static NlResult commit_one_set(NlSocket& sock, uint32_t family, const char* table,
                               const char* name, const SetDef& sd, bool ipv6,
                               bool per_element_counters, uint32_t set_id) {
    uint32_t key_type = 0, key_len = 0;
    const uint8_t* concat_fields = nullptr;
    size_t concat_count = 0;
    set_key_params(sd, ipv6, key_type, key_len, concat_fields, concat_count);
    const bool is_interval = (sd.kind != SetKind::OutPort);

    auto try_netlink = [&](bool use_concat_flag) -> NlResult {
        NlBatch batch;
        if (!batch.is_valid())
            return {false, "failed to allocate batch"};
        if (!add_set(batch, family, table, name, key_type, key_len, set_id,
                     is_interval, concat_fields, concat_count, per_element_counters,
                     use_concat_flag))
            return {false, std::string("failed to build set ") + table + '/' + name};
        return batch.execute(sock);
    };

    NlResult result = try_netlink(/*use_concat_flag=*/true);
    if (result.success || sd.kind != SetKind::OutPort || result.error_code != EINVAL)
        return result;

    // RouterOS 5.6 accepts the concat descriptor but rejects NFT_SET_CONCAT.
    // Retry the same native netlink request without this newer flag. A rejected
    // netlink batch is atomic, so the first attempt leaves no partial set.
    NlResult compat_result = try_netlink(/*use_concat_flag=*/false);
    return compat_result.success ? compat_result : result;
}

NlResult CreateTableOp::execute(NlSocket& sock) {
    // RouterOS / constrained kernels need small netlink transactions:

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

    // Phase 2: tables + named counters
    {
        NlBatch batch;
        if (!batch.is_valid())
            return {false, "failed to allocate batch"};

        if (!add_table(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), NFT_MSG_NEWTABLE, NLM_F_CREATE)
            || !add_table(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), NFT_MSG_NEWTABLE, NLM_F_CREATE))
            return {false, "failed to build tables"};

        if (!add_counter_obj(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), COUNTER_NAME)
            || !add_counter_obj(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), COUNTER_NAME))
            return {false, "failed to build 'processed' counter"};

        for (const auto& sd : cfg_->sets) {
            if (!add_counter_obj(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), sd.name.c_str())
                || !add_counter_obj(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), sd.name_v6.c_str()))
                return {false, "failed to build counter for set '" + sd.name + "'"};
        }

        NlResult res = batch.execute(sock);
        if (!res.success) return res;
    }

    // Phase 3: each set in its own batch (RouterOS-safe).
    // Non-zero SET_ID required on RouterOS even for single-set batches.
    // Some older kernels reject NFT_SET_EXPR. If the first creation attempt
    // reports EINVAL, restart from scratch without optional per-element
    // counters so callers do not need a kernel-specific configuration switch.
    auto retry_without_element_counters = [&](const NlResult& original) -> NlResult {
        if (!cfg_->per_element_counters || original.error_code != EINVAL)
            return original;

        auto fallback_config = std::make_shared<nft::NftConfig>(*cfg_);
        fallback_config->per_element_counters = false;
        CreateTableOp fallback(std::move(fallback_config));
        NlResult fallback_result = fallback.execute(sock);
        return fallback_result.success ? fallback_result : original;
    };

    uint32_t sid = 1;
    for (const auto& sd : cfg_->sets) {
        NlResult r4 = commit_one_set(sock, NFPROTO_IPV4, cfg_->table_v4.c_str(),
                                     sd.name.c_str(), sd, /*ipv6=*/false,
                                     cfg_->per_element_counters, sid++);
        if (!r4.success) return retry_without_element_counters(r4);
        NlResult r6 = commit_one_set(sock, NFPROTO_IPV6, cfg_->table_v6.c_str(),
                                     sd.name_v6.c_str(), sd, /*ipv6=*/true,
                                     cfg_->per_element_counters, sid++);
        if (!r6.success) return retry_without_element_counters(r6);
    }

    // Phase 4: chains
    {
        NlBatch batch;
        if (!batch.is_valid())
            return {false, "failed to allocate batch"};

        if (!add_chain(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_INPUT, NF_INET_LOCAL_IN)
            || !add_chain(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_FORWARD, NF_INET_FORWARD)
            || !add_chain(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_OUTPUT, NF_INET_LOCAL_OUT)
            || !add_chain(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_INPUT, NF_INET_LOCAL_IN)
            || !add_chain(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_FORWARD, NF_INET_FORWARD)
            || !add_chain(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_OUTPUT, NF_INET_LOCAL_OUT))
            return {false, "failed to build chains"};

        NlResult res = batch.execute(sock);
        if (!res.success) return res;
    }

    // Phase 5: rules (all objects committed; resolve sets by name only)
    {
        NlBatch batch;
        if (!batch.is_valid())
            return {false, "failed to allocate batch"};

        if (!add_rule_counter_ref(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_INPUT)
            || !add_rule_counter_ref(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_FORWARD)
            || !add_rule_counter_ref(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_INPUT)
            || !add_rule_counter_ref(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_FORWARD))
            return {false, "failed to build 'processed' counter rules"};

        for (const auto& sd : cfg_->sets) {
            const char* lp = sd.log_prefix.c_str();
            switch (sd.kind) {
            case SetKind::InIP:
                if (!add_rule_in_ip(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_INPUT,
                                    sd.name.c_str(), 0,
                                    IPV4_SRC_OFFSET, IPV4_ADDR_LEN, lp, sd.name.c_str())
                    || !add_rule_in_ip(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_FORWARD,
                                       sd.name.c_str(), 0,
                                       IPV4_SRC_OFFSET, IPV4_ADDR_LEN, lp, sd.name.c_str())
                    || !add_rule_in_ip(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_INPUT,
                                       sd.name_v6.c_str(), 0,
                                       IPV6_SRC_OFFSET, IPV6_ADDR_LEN, lp, sd.name_v6.c_str())
                    || !add_rule_in_ip(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_FORWARD,
                                       sd.name_v6.c_str(), 0,
                                       IPV6_SRC_OFFSET, IPV6_ADDR_LEN, lp, sd.name_v6.c_str()))
                    return {false, "failed to build rules for set '" + sd.name + "'"};
                break;

            case SetKind::OutIP:
                if (!add_rule_out_ip(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_OUTPUT,
                                     sd.name.c_str(), 0,
                                     IPV4_DST_OFFSET, IPV4_ADDR_LEN,
                                     sd.name.c_str())
                    || !add_rule_out_ip(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_OUTPUT,
                                        sd.name_v6.c_str(), 0,
                                        IPV6_DST_OFFSET, IPV6_ADDR_LEN,
                                        sd.name_v6.c_str()))
                    return {false, "failed to build output rules for set '" + sd.name + "'"};
                break;

            case SetKind::OutPort:
                if (!add_rule_out_port_concat(batch, NFPROTO_IPV4, cfg_->table_v4.c_str(), CHAIN_OUTPUT,
                                              sd.name.c_str(), 0, sd.name.c_str())
                    || !add_rule_out_port_concat(batch, NFPROTO_IPV6, cfg_->table_v6.c_str(), CHAIN_OUTPUT,
                                                 sd.name_v6.c_str(), 0, sd.name_v6.c_str()))
                    return {false, "failed to build port rules for set '" + sd.name + "'"};
                break;
            }
        }

        return batch.execute(sock);
    }
}


// DeleteTableOp
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
