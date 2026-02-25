#pragma once

// RAII wrappers for libnftnl C objects.
//
// These wrappers use std::unique_ptr with custom deleters to ensure that
// libnftnl objects are properly freed when they go out of scope.
//
// Wrapped types:
//   - nftnl_table  (freed via nftnl_table_free)
//   - nftnl_chain  (freed via nftnl_chain_free)
//   - nftnl_set    (freed via nftnl_set_free)
//   - nftnl_rule   (freed via nftnl_rule_free)
//
// Intentionally NOT wrapped:
//   - nftnl_expr     — nftnl_rule_add_expr(rule, expr) transfers ownership
//                       of the expr to the rule. Wrapping it would cause a
//                       double-free when the rule is destroyed.
//   - nftnl_set_elem — nftnl_set_elem_add(set, elem) transfers ownership
//                       of the elem to the set. Wrapping it would cause a
//                       double-free when the set is destroyed.

extern "C" {
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/set.h>
#include <libnftnl/rule.h>
}

#include <memory>

namespace nft {

// --- Table -------------------------------------------------------------------

struct NftnlTableDeleter {
    void operator()(struct nftnl_table* t) const noexcept { nftnl_table_free(t); }
};
using UniqueTable = std::unique_ptr<struct nftnl_table, NftnlTableDeleter>;

inline UniqueTable make_table() { return UniqueTable(nftnl_table_alloc()); }

// --- Chain -------------------------------------------------------------------

struct NftnlChainDeleter {
    void operator()(struct nftnl_chain* c) const noexcept { nftnl_chain_free(c); }
};
using UniqueChain = std::unique_ptr<struct nftnl_chain, NftnlChainDeleter>;

inline UniqueChain make_chain() { return UniqueChain(nftnl_chain_alloc()); }

// --- Set ---------------------------------------------------------------------

struct NftnlSetDeleter {
    void operator()(struct nftnl_set* s) const noexcept { nftnl_set_free(s); }
};
using UniqueSet = std::unique_ptr<struct nftnl_set, NftnlSetDeleter>;

inline UniqueSet make_set() { return UniqueSet(nftnl_set_alloc()); }

// --- Rule --------------------------------------------------------------------

struct NftnlRuleDeleter {
    void operator()(struct nftnl_rule* r) const noexcept { nftnl_rule_free(r); }
};
using UniqueRule = std::unique_ptr<struct nftnl_rule, NftnlRuleDeleter>;

inline UniqueRule make_rule() { return UniqueRule(nftnl_rule_alloc()); }

} // namespace nft
