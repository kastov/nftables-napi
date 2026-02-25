#pragma once

#include <string>

namespace nft {

enum class TargetSet {
    Blacklist,
    Droplist
};

struct NftConfig {
    std::string table_v4;
    std::string table_v6;
    std::string set_v4;
    std::string set_v6;
    std::string drop_set_v4;
    std::string drop_set_v6;
    std::string blacklist_log_prefix;
    std::string droplist_log_prefix;

    static NftConfig from_names(const std::string& table_name,
                                const std::string& blacklist_set_name,
                                const std::string& droplist_set_name) {
        return {table_name, table_name + "6",
                blacklist_set_name, blacklist_set_name + "6",
                droplist_set_name, droplist_set_name + "6",
                blacklist_set_name + ": ",
                droplist_set_name + ": "};
    }

    const std::string& resolve_set_v4(TargetSet ts) const {
        return (ts == TargetSet::Blacklist) ? set_v4 : drop_set_v4;
    }
    const std::string& resolve_set_v6(TargetSet ts) const {
        return (ts == TargetSet::Blacklist) ? set_v6 : drop_set_v6;
    }
    const std::string& resolve_log_prefix(TargetSet ts) const {
        return (ts == TargetSet::Blacklist) ? blacklist_log_prefix : droplist_log_prefix;
    }
};

} // namespace nft
