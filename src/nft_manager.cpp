#include "nft_manager.h"
#include "validation.h"
#include "workers/nft_worker.h"
#include "netlink/parsed_addr.h"
#include "netlink/table_ops.h"
#include "netlink/set_ops.h"
#include "netlink/constants.h"

#include <cmath>
#include <cstring>
#include <optional>
#include <vector>

static constexpr double MAX_TIMEOUT_SEC = 4294967295.0; // UINT32_MAX seconds (~136 years)

static ParsedAddr to_parsed_addr(const IpAddr& addr) {
    ParsedAddr pa{};
    pa.family = (addr.family == IpFamily::IPv4) ? nft::FAMILY_IPV4 : nft::FAMILY_IPV6;
    pa.len = addr.len;
    std::memcpy(pa.bytes, addr.bytes.data(), addr.len);
    return pa;
}

static std::vector<ParsedAddr> parse_ip_array(Napi::Env env, Napi::Array arr) {
    std::vector<ParsedAddr> addrs;
    addrs.reserve(arr.Length());

    for (uint32_t i = 0; i < arr.Length(); ++i) {
        Napi::Value val = arr[i];
        if (!val.IsString()) {
            Napi::TypeError::New(env, "each element must be a string")
                .ThrowAsJavaScriptException();
            return {};
        }

        std::string ip = val.As<Napi::String>().Utf8Value();
        IpAddr addr = parse_ip(ip);
        if (addr.family == IpFamily::Invalid) {
            Napi::Error::New(env, "Invalid IP address at index " + std::to_string(i) + ": " + ip)
                .ThrowAsJavaScriptException();
            return {};
        }

        addrs.push_back(to_parsed_addr(addr));
    }

    return addrs;
}

// Parse set name, filtering by allowed SetKind values.
// allow_ip=true matches InIP and OutIP; allow_port=true matches OutPort.
static std::optional<size_t> parse_set_name(Napi::Env env, Napi::Object opts,
                                             const char* method_name,
                                             const nft::NftConfig& cfg,
                                             bool allow_ip, bool allow_port) {
    if (!opts.Has("set") || !opts.Get("set").IsString()) {
        std::string msg = std::string(method_name) + ": 'set' is required and must be a string";
        Napi::TypeError::New(env, msg).ThrowAsJavaScriptException();
        return std::nullopt;
    }
    std::string set_str = opts.Get("set").As<Napi::String>().Utf8Value();

    for (size_t i = 0; i < cfg.sets.size(); ++i) {
        if (cfg.sets[i].name != set_str) continue;
        bool is_ip = (cfg.sets[i].kind == nft::SetKind::InIP || cfg.sets[i].kind == nft::SetKind::OutIP);
        bool is_port = (cfg.sets[i].kind == nft::SetKind::OutPort);
        if ((allow_ip && is_ip) || (allow_port && is_port)) return i;
    }

    // Build valid names for error message
    std::string valid;
    for (size_t i = 0; i < cfg.sets.size(); ++i) {
        bool is_ip = (cfg.sets[i].kind == nft::SetKind::InIP || cfg.sets[i].kind == nft::SetKind::OutIP);
        bool is_port = (cfg.sets[i].kind == nft::SetKind::OutPort);
        if (!((allow_ip && is_ip) || (allow_port && is_port))) continue;
        if (!valid.empty()) valid += ", ";
        valid += "'" + cfg.sets[i].name + "'";
    }
    std::string msg = std::string(method_name) + ": 'set' must be one of: " + valid;
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return std::nullopt;
}

// Returns timeout in ms (0 = permanent/no timeout). Sets JS exception on error.
static std::optional<uint64_t> parse_timeout(Napi::Env env, Napi::Object opts, const char* method_name) {
    if (!opts.Has("timeout") || opts.Get("timeout").IsUndefined() || opts.Get("timeout").IsNull()) {
        return uint64_t{0}; // permanent
    }
    Napi::Value tv = opts.Get("timeout");
    if (!tv.IsNumber()) {
        std::string msg = std::string(method_name) + ": 'timeout' must be a number (seconds)";
        Napi::TypeError::New(env, msg).ThrowAsJavaScriptException();
        return std::nullopt;
    }
    double timeout_sec = tv.As<Napi::Number>().DoubleValue();
    if (std::isnan(timeout_sec) || timeout_sec <= 0 || timeout_sec > MAX_TIMEOUT_SEC) {
        std::string msg = std::string(method_name) + ": 'timeout' must be a positive number (seconds)";
        Napi::Error::New(env, msg).ThrowAsJavaScriptException();
        return std::nullopt;
    }
    return static_cast<uint64_t>(timeout_sec * 1000.0);
}

// Parse a single port from opts.port
static std::optional<uint16_t> parse_port_value(Napi::Env env, Napi::Object opts,
                                                 const char* method_name) {
    if (!opts.Has("port") || !opts.Get("port").IsNumber()) {
        std::string msg = std::string(method_name) + ": 'port' is required and must be a number";
        Napi::TypeError::New(env, msg).ThrowAsJavaScriptException();
        return std::nullopt;
    }
    double val = opts.Get("port").As<Napi::Number>().DoubleValue();
    PortVal pv = parse_port(val);
    if (!pv.valid) {
        Napi::Error::New(env, std::string(method_name) + ": 'port' must be an integer 0-65535")
            .ThrowAsJavaScriptException();
        return std::nullopt;
    }
    return pv.port;
}

// Parse array of ports from opts.ports
static std::vector<uint16_t> parse_port_array(Napi::Env env, Napi::Array arr,
                                               const char* method_name) {
    std::vector<uint16_t> ports;
    ports.reserve(arr.Length());

    for (uint32_t i = 0; i < arr.Length(); ++i) {
        Napi::Value val = arr[i];
        if (!val.IsNumber()) {
            Napi::TypeError::New(env, std::string(method_name) + ": each port must be a number")
                .ThrowAsJavaScriptException();
            return {};
        }
        double d = val.As<Napi::Number>().DoubleValue();
        PortVal pv = parse_port(d);
        if (!pv.valid) {
            Napi::Error::New(env, std::string(method_name) +
                ": invalid port at index " + std::to_string(i))
                .ThrowAsJavaScriptException();
            return {};
        }
        ports.push_back(pv.port);
    }
    return ports;
}

// Parse optional protocol: 'tcp', 'udp', or absent (both).
// Returns 0 for both, PROTO_TCP for tcp, PROTO_UDP for udp.
// Returns 255 on error (after throwing JS exception).
static uint8_t parse_protocol(Napi::Env env, Napi::Object opts, const char* method_name) {
    if (!opts.Has("protocol") || opts.Get("protocol").IsUndefined() || opts.Get("protocol").IsNull()) {
        return 0; // both
    }
    Napi::Value pv = opts.Get("protocol");
    if (!pv.IsString()) {
        std::string msg = std::string(method_name) + ": 'protocol' must be 'tcp' or 'udp'";
        Napi::TypeError::New(env, msg).ThrowAsJavaScriptException();
        return 255;
    }
    std::string proto = pv.As<Napi::String>().Utf8Value();
    if (proto == "tcp") return nft::PROTO_TCP;
    if (proto == "udp") return nft::PROTO_UDP;
    std::string msg = std::string(method_name) + ": 'protocol' must be 'tcp' or 'udp'";
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return 255;
}

static std::vector<PortElem> make_port_elems(uint16_t port, uint8_t proto) {
    if (proto == 0) {
        return {{nft::PROTO_TCP, port}, {nft::PROTO_UDP, port}};
    }
    return {{proto, port}};
}

static std::vector<PortElem> make_port_elems_bulk(const std::vector<uint16_t>& ports, uint8_t proto) {
    std::vector<PortElem> elems;
    if (proto == 0) {
        elems.reserve(ports.size() * 2);
        for (uint16_t p : ports) {
            elems.push_back({nft::PROTO_TCP, p});
            elems.push_back({nft::PROTO_UDP, p});
        }
    } else {
        elems.reserve(ports.size());
        for (uint16_t p : ports) {
            elems.push_back({proto, p});
        }
    }
    return elems;
}

// Helper: parse optional string array from opts, returns empty vector if not present
static std::vector<std::string> parse_optional_string_array(Napi::Env env, Napi::Object opts,
                                                             const char* field_name,
                                                             const char* context) {
    if (!opts.Has(field_name) || opts.Get(field_name).IsUndefined() || opts.Get(field_name).IsNull()) {
        return {};
    }
    Napi::Value val = opts.Get(field_name);
    if (!val.IsArray()) {
        std::string msg = std::string(context) + ": '" + field_name + "' must be an array of strings";
        Napi::TypeError::New(env, msg).ThrowAsJavaScriptException();
        return {};
    }
    Napi::Array arr = val.As<Napi::Array>();
    std::vector<std::string> result;
    result.reserve(arr.Length());
    for (uint32_t i = 0; i < arr.Length(); ++i) {
        Napi::Value v = arr[i];
        if (!v.IsString()) {
            std::string msg = std::string(context) + ": '" + field_name + "[" + std::to_string(i) + "]' must be a string";
            Napi::TypeError::New(env, msg).ThrowAsJavaScriptException();
            return {};
        }
        std::string name = v.As<Napi::String>().Utf8Value();
        if (name.empty()) {
            std::string msg = std::string(context) + ": '" + field_name + "[" + std::to_string(i) + "]' must not be empty";
            Napi::Error::New(env, msg).ThrowAsJavaScriptException();
            return {};
        }
        result.push_back(std::move(name));
    }
    return result;
}

Napi::Object NftManager::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "NftManager", {
        InstanceMethod<&NftManager::CreateTable>("createTable"),
        InstanceMethod<&NftManager::AddAddress>("addAddress"),
        InstanceMethod<&NftManager::RemoveAddress>("removeAddress"),
        InstanceMethod<&NftManager::AddAddresses>("addAddresses"),
        InstanceMethod<&NftManager::RemoveAddresses>("removeAddresses"),
        InstanceMethod<&NftManager::DeleteTable>("deleteTable"),
        InstanceMethod<&NftManager::AddPort>("addPort"),
        InstanceMethod<&NftManager::RemovePort>("removePort"),
        InstanceMethod<&NftManager::AddPorts>("addPorts"),
        InstanceMethod<&NftManager::RemovePorts>("removePorts"),
    });

    env.SetInstanceData(new Napi::FunctionReference(Napi::Persistent(func)));

    exports.Set("NftManager", func);
    return exports;
}

NftManager::NftManager(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<NftManager>(info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env,
            "NftManager requires options object with tableName and sets")
            .ThrowAsJavaScriptException();
        return;
    }

    Napi::Object opts = info[0].As<Napi::Object>();

    // tableName — required string
    if (!opts.Has("tableName") || !opts.Get("tableName").IsString()) {
        Napi::TypeError::New(env, "NftManager: 'tableName' is required and must be a string")
            .ThrowAsJavaScriptException();
        return;
    }

    // sets — required non-empty array
    if (!opts.Has("sets") || !opts.Get("sets").IsArray()) {
        Napi::TypeError::New(env, "NftManager: 'sets' is required and must be an array of strings")
            .ThrowAsJavaScriptException();
        return;
    }

    Napi::Array sets_arr = opts.Get("sets").As<Napi::Array>();
    uint32_t len = sets_arr.Length();

    if (len == 0) {
        Napi::Error::New(env, "NftManager: 'sets' must contain at least one set name")
            .ThrowAsJavaScriptException();
        return;
    }

    // Parse required sets (InIP)
    std::vector<std::string> in_sets;
    in_sets.reserve(len);
    for (uint32_t i = 0; i < len; ++i) {
        Napi::Value val = sets_arr[i];
        if (!val.IsString()) {
            Napi::TypeError::New(env, "NftManager: 'sets[" + std::to_string(i) + "]' must be a string")
                .ThrowAsJavaScriptException();
            return;
        }
        std::string name = val.As<Napi::String>().Utf8Value();
        if (name.empty()) {
            Napi::Error::New(env, "NftManager: 'sets[" + std::to_string(i) + "]' must not be empty")
                .ThrowAsJavaScriptException();
            return;
        }
        in_sets.push_back(std::move(name));
    }

    // Parse optional outSets (OutIP)
    std::vector<std::string> out_sets = parse_optional_string_array(env, opts, "outSets", "NftManager");
    if (env.IsExceptionPending()) return;

    // Parse optional outPortSets (OutPort)
    std::vector<std::string> out_port_sets = parse_optional_string_array(env, opts, "outPortSets", "NftManager");
    if (env.IsExceptionPending()) return;

    // Cross-array duplicate check: all names must be unique across all arrays
    std::vector<std::string> all_names;
    all_names.reserve(in_sets.size() + out_sets.size() + out_port_sets.size());
    all_names.insert(all_names.end(), in_sets.begin(), in_sets.end());
    all_names.insert(all_names.end(), out_sets.begin(), out_sets.end());
    all_names.insert(all_names.end(), out_port_sets.begin(), out_port_sets.end());
    for (size_t i = 0; i < all_names.size(); ++i) {
        for (size_t j = i + 1; j < all_names.size(); ++j) {
            if (all_names[i] == all_names[j]) {
                Napi::Error::New(env, "NftManager: duplicate set name '" + all_names[i] + "'")
                    .ThrowAsJavaScriptException();
                return;
            }
        }
    }

    std::string table_name = opts.Get("tableName").As<Napi::String>().Utf8Value();

    config_ = std::make_shared<const nft::NftConfig>(
        nft::NftConfig::from_names(table_name, in_sets, out_sets, out_port_sets));

    sock_ = std::make_shared<NlSocket>();

    if (!sock_->is_valid()) {
        Napi::Error::New(env, "Failed to open netlink socket. Ensure CAP_NET_ADMIN or root.")
            .ThrowAsJavaScriptException();
        return;
    }

    valid_ = true;
}

// ── Table lifecycle ─────────────────────────────────────────────────────────

Napi::Value NftManager::CreateTable(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::make_unique<CreateTableOp>(config_), std::move(deferred));
    return promise;
}

Napi::Value NftManager::DeleteTable(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::make_unique<DeleteTableOp>(config_), std::move(deferred));
    return promise;
}

// ── IP address operations ───────────────────────────────────────────────────

Napi::Value NftManager::AddAddress(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "addAddress requires an options object: { ip, set, timeout? }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Object opts = info[0].As<Napi::Object>();

    if (!opts.Has("ip") || !opts.Get("ip").IsString()) {
        Napi::TypeError::New(env, "addAddress: 'ip' is required and must be a string")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string ip = opts.Get("ip").As<Napi::String>().Utf8Value();

    auto set_idx = parse_set_name(env, opts, "addAddress", *config_, true, false);
    if (!set_idx) return env.Undefined();

    auto timeout_ms = parse_timeout(env, opts, "addAddress");
    if (!timeout_ms) return env.Undefined();

    IpAddr addr = parse_ip(ip);
    if (addr.family == IpFamily::Invalid) {
        Napi::Error::New(env, "Invalid IP address: " + ip).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::vector<ParsedAddr> addrs;
    addrs.push_back(to_parsed_addr(addr));
    auto op = std::make_unique<BulkAddSetElemOp>(std::move(addrs), *timeout_ms, config_, *set_idx);

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::RemoveAddress(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "removeAddress requires an options object: { ip, set }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Object opts = info[0].As<Napi::Object>();

    if (!opts.Has("ip") || !opts.Get("ip").IsString()) {
        Napi::TypeError::New(env, "removeAddress: 'ip' is required and must be a string")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string ip = opts.Get("ip").As<Napi::String>().Utf8Value();

    auto set_idx = parse_set_name(env, opts, "removeAddress", *config_, true, false);
    if (!set_idx) return env.Undefined();

    IpAddr addr = parse_ip(ip);
    if (addr.family == IpFamily::Invalid) {
        Napi::Error::New(env, "Invalid IP address: " + ip).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::vector<ParsedAddr> addrs;
    addrs.push_back(to_parsed_addr(addr));
    auto op = std::make_unique<BulkDelSetElemOp>(std::move(addrs), config_, *set_idx);

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::AddAddresses(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "addAddresses requires an options object: { ips, set, timeout? }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Object opts = info[0].As<Napi::Object>();

    if (!opts.Has("ips") || !opts.Get("ips").IsArray()) {
        Napi::TypeError::New(env, "addAddresses: 'ips' is required and must be an array of strings")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Array arr = opts.Get("ips").As<Napi::Array>();

    auto set_idx = parse_set_name(env, opts, "addAddresses", *config_, true, false);
    if (!set_idx) return env.Undefined();

    auto timeout_ms = parse_timeout(env, opts, "addAddresses");
    if (!timeout_ms) return env.Undefined();

    std::vector<ParsedAddr> addrs = parse_ip_array(env, arr);
    if (env.IsExceptionPending()) return env.Undefined();

    if (addrs.empty()) {
        auto deferred = Napi::Promise::Deferred::New(env);
        auto promise = deferred.Promise();
        deferred.Resolve(env.Undefined());
        return promise;
    }

    auto op = std::make_unique<BulkAddSetElemOp>(std::move(addrs), *timeout_ms, config_, *set_idx);
    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::RemoveAddresses(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "removeAddresses requires an options object: { ips, set }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Object opts = info[0].As<Napi::Object>();

    if (!opts.Has("ips") || !opts.Get("ips").IsArray()) {
        Napi::TypeError::New(env, "removeAddresses: 'ips' is required and must be an array of strings")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Array arr = opts.Get("ips").As<Napi::Array>();

    auto set_idx = parse_set_name(env, opts, "removeAddresses", *config_, true, false);
    if (!set_idx) return env.Undefined();

    std::vector<ParsedAddr> addrs = parse_ip_array(env, arr);
    if (env.IsExceptionPending()) return env.Undefined();

    if (addrs.empty()) {
        auto deferred = Napi::Promise::Deferred::New(env);
        auto promise = deferred.Promise();
        deferred.Resolve(env.Undefined());
        return promise;
    }

    auto op = std::make_unique<BulkDelSetElemOp>(std::move(addrs), config_, *set_idx);
    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

// ── Port operations ─────────────────────────────────────────────────────────

Napi::Value NftManager::AddPort(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "addPort requires an options object: { port, set, timeout? }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Object opts = info[0].As<Napi::Object>();

    auto port = parse_port_value(env, opts, "addPort");
    if (!port) return env.Undefined();

    auto set_idx = parse_set_name(env, opts, "addPort", *config_, false, true);
    if (!set_idx) return env.Undefined();

    uint8_t proto = parse_protocol(env, opts, "addPort");
    if (proto == 255) return env.Undefined();

    auto timeout_ms = parse_timeout(env, opts, "addPort");
    if (!timeout_ms) return env.Undefined();

    auto elems = make_port_elems(*port, proto);
    auto op = std::make_unique<BulkAddPortElemOp>(std::move(elems), *timeout_ms, config_, *set_idx);

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::RemovePort(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "removePort requires an options object: { port, set }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Object opts = info[0].As<Napi::Object>();

    auto port = parse_port_value(env, opts, "removePort");
    if (!port) return env.Undefined();

    auto set_idx = parse_set_name(env, opts, "removePort", *config_, false, true);
    if (!set_idx) return env.Undefined();

    uint8_t proto = parse_protocol(env, opts, "removePort");
    if (proto == 255) return env.Undefined();

    auto elems = make_port_elems(*port, proto);
    auto op = std::make_unique<BulkDelPortElemOp>(std::move(elems), config_, *set_idx);

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::AddPorts(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "addPorts requires an options object: { ports, set, timeout? }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Object opts = info[0].As<Napi::Object>();

    if (!opts.Has("ports") || !opts.Get("ports").IsArray()) {
        Napi::TypeError::New(env, "addPorts: 'ports' is required and must be an array of numbers")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Array arr = opts.Get("ports").As<Napi::Array>();

    auto set_idx = parse_set_name(env, opts, "addPorts", *config_, false, true);
    if (!set_idx) return env.Undefined();

    uint8_t proto = parse_protocol(env, opts, "addPorts");
    if (proto == 255) return env.Undefined();

    auto timeout_ms = parse_timeout(env, opts, "addPorts");
    if (!timeout_ms) return env.Undefined();

    std::vector<uint16_t> ports = parse_port_array(env, arr, "addPorts");
    if (env.IsExceptionPending()) return env.Undefined();

    if (ports.empty()) {
        auto deferred = Napi::Promise::Deferred::New(env);
        auto promise = deferred.Promise();
        deferred.Resolve(env.Undefined());
        return promise;
    }

    auto elems = make_port_elems_bulk(ports, proto);
    auto op = std::make_unique<BulkAddPortElemOp>(std::move(elems), *timeout_ms, config_, *set_idx);
    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::RemovePorts(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!valid_) {
        Napi::Error::New(env, "NftManager is not initialized").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "removePorts requires an options object: { ports, set }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Object opts = info[0].As<Napi::Object>();

    if (!opts.Has("ports") || !opts.Get("ports").IsArray()) {
        Napi::TypeError::New(env, "removePorts: 'ports' is required and must be an array of numbers")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Array arr = opts.Get("ports").As<Napi::Array>();

    auto set_idx = parse_set_name(env, opts, "removePorts", *config_, false, true);
    if (!set_idx) return env.Undefined();

    uint8_t proto = parse_protocol(env, opts, "removePorts");
    if (proto == 255) return env.Undefined();

    std::vector<uint16_t> ports = parse_port_array(env, arr, "removePorts");
    if (env.IsExceptionPending()) return env.Undefined();

    if (ports.empty()) {
        auto deferred = Napi::Promise::Deferred::New(env);
        auto promise = deferred.Promise();
        deferred.Resolve(env.Undefined());
        return promise;
    }

    auto elems = make_port_elems_bulk(ports, proto);
    auto op = std::make_unique<BulkDelPortElemOp>(std::move(elems), config_, *set_idx);
    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

// ── Queue management ────────────────────────────────────────────────────────

void NftManager::Enqueue(std::unique_ptr<NlOperation> op, Napi::Promise::Deferred deferred) {
    queue_.push({std::move(op), std::move(deferred)});
    DrainQueue();
}

void NftManager::DrainQueue() {
    if (worker_active_ || queue_.empty()) return;

    worker_active_ = true;
    this->Ref();

    auto pending = std::move(queue_.front());
    queue_.pop();

    auto* worker = new NftWorker(
        Env(), sock_, std::move(pending.op), std::move(pending.deferred), this);
    worker->Queue();
}

void NftManager::OnWorkerDone() {
    worker_active_ = false;
    this->Unref();
    DrainQueue();
}
