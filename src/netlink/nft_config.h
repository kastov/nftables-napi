#pragma once

#include <string>
#include <vector>

namespace nft {

enum class SetKind { InIP, OutIP, OutPort };

struct SetDef {
    std::string name;
    std::string name_v6;
    std::string log_prefix;  // non-empty for InIP only
    SetKind kind;
};

struct NftConfig {
    std::string table_v4;
    std::string table_v6;
    std::vector<SetDef> sets;  // all sets: InIP + OutIP + OutPort
    bool per_element_counters = true;

    static NftConfig from_names(const std::string& table_name,
                                const std::vector<std::string>& in_sets,
                                const std::vector<std::string>& out_sets,
                                const std::vector<std::string>& out_port_sets,
                                bool per_element_counters = true) {
        NftConfig cfg;
        cfg.table_v4 = table_name;
        cfg.table_v6 = table_name + "6";
        cfg.per_element_counters = per_element_counters;
        cfg.sets.reserve(in_sets.size() + out_sets.size() + out_port_sets.size());
        for (const auto& n : in_sets) {
            cfg.sets.push_back({n, n + "6", n + ": ", SetKind::InIP});
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
