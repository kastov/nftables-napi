#pragma once

#include <string>
#include <vector>

namespace nft {

enum class SetKind { InIP, OutIP, OutPort };

struct SetDef {
    std::string name;
    std::string name_v6;
    // Log prefix for the generated rule. Empty means "no log expression at all"
    // (never emitted into the rule). Always empty for OutIP/OutPort; empty for
    // InIP as well when logging is disabled.
    std::string log_prefix;
    SetKind kind;
};

struct NftConfig {
    std::string table_v4;
    std::string table_v6;
    std::vector<SetDef> sets;  // all sets: InIP + OutIP + OutPort
    // Emit `ct direction reply accept` at the top of the input and forward
    // chains, so reply traffic to locally-originated connections is not matched
    // against the ingress sets. Packets of connections opened *to* this host
    // stay subject to the sets in both directions. Does not affect the output
    // chain.
    bool accept_reply_traffic = true;

    static NftConfig from_names(const std::string& table_name,
                                const std::vector<std::string>& in_sets,
                                const std::vector<std::string>& out_sets,
                                const std::vector<std::string>& out_port_sets,
                                bool logging = true,
                                bool accept_reply_traffic = true) {
        NftConfig cfg;
        cfg.table_v4 = table_name;
        cfg.table_v6 = table_name + "6";
        cfg.accept_reply_traffic = accept_reply_traffic;
        cfg.sets.reserve(in_sets.size() + out_sets.size() + out_port_sets.size());
        for (const auto& n : in_sets) {
            cfg.sets.push_back({n, n + "6", logging ? n + ": " : std::string(), SetKind::InIP});
        }
        for (const auto& n : out_sets) {
            cfg.sets.push_back({n, n + "6", "", SetKind::OutIP});
        }
        for (const auto& n : out_port_sets) {
            cfg.sets.push_back({n, n + "6", "", SetKind::OutPort});
        }
        return cfg;
    }
};

} // namespace nft
