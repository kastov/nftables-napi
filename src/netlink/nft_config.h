#pragma once

#include <string>
#include <vector>

namespace nft {

struct SetDef {
    std::string name;        // user-facing key = nftables IPv4 set name
    std::string name_v6;     // name + "6"
    std::string log_prefix;  // name + ": "
};

struct NftConfig {
    std::string table_v4;
    std::string table_v6;
    std::vector<SetDef> sets;

    static NftConfig from_names(const std::string& table_name,
                                const std::vector<std::string>& set_names) {
        NftConfig cfg;
        cfg.table_v4 = table_name;
        cfg.table_v6 = table_name + "6";
        cfg.sets.reserve(set_names.size());
        for (const auto& n : set_names) {
            cfg.sets.push_back({n, n + "6", n + ": "});
        }
        return cfg;
    }
};

} // namespace nft
