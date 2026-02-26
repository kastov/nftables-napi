#include "nft_manager.h"
#include "validation.h"
#include "workers/nft_worker.h"
#include "netlink/parsed_addr.h"
#include "netlink/table_ops.h"
#include "netlink/set_ops.h"

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

static std::optional<size_t> parse_set_name(Napi::Env env, Napi::Object opts,
                                             const char* method_name,
                                             const nft::NftConfig& cfg) {
    if (!opts.Has("set") || !opts.Get("set").IsString()) {
        std::string msg = std::string(method_name) + ": 'set' is required and must be a string";
        Napi::TypeError::New(env, msg).ThrowAsJavaScriptException();
        return std::nullopt;
    }
    std::string set_str = opts.Get("set").As<Napi::String>().Utf8Value();

    for (size_t i = 0; i < cfg.sets.size(); ++i) {
        if (cfg.sets[i].name == set_str) return i;
    }

    std::string valid;
    for (size_t i = 0; i < cfg.sets.size(); ++i) {
        if (i > 0) valid += ", ";
        valid += "'" + cfg.sets[i].name + "'";
    }
    std::string msg = std::string(method_name) + ": 'set' must be one of: " + valid;
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return std::nullopt;
}

// Returns timeout in ms (0 = permanent/no timeout). Sets JS exception on error.
// Returns std::nullopt on error.
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

Napi::Object NftManager::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "NftManager", {
        InstanceMethod<&NftManager::CreateTable>("createTable"),
        InstanceMethod<&NftManager::AddAddress>("addAddress"),
        InstanceMethod<&NftManager::RemoveAddress>("removeAddress"),
        InstanceMethod<&NftManager::AddAddresses>("addAddresses"),
        InstanceMethod<&NftManager::RemoveAddresses>("removeAddresses"),
        InstanceMethod<&NftManager::DeleteTable>("deleteTable"),
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

    if (!opts.Has("tableName") || !opts.Get("tableName").IsString()) {
        Napi::TypeError::New(env, "NftManager: 'tableName' is required and must be a string")
            .ThrowAsJavaScriptException();
        return;
    }

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

    std::vector<std::string> set_names;
    set_names.reserve(len);

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
        for (size_t j = 0; j < set_names.size(); ++j) {
            if (set_names[j] == name) {
                Napi::Error::New(env, "NftManager: duplicate set name '" + name + "'")
                    .ThrowAsJavaScriptException();
                return;
            }
        }
        set_names.push_back(std::move(name));
    }

    std::string table_name = opts.Get("tableName").As<Napi::String>().Utf8Value();

    config_ = std::make_shared<const nft::NftConfig>(
        nft::NftConfig::from_names(table_name, set_names));

    sock_ = std::make_shared<NlSocket>();

    if (!sock_->is_valid()) {
        Napi::Error::New(env, "Failed to open netlink socket. Ensure CAP_NET_ADMIN or root.")
            .ThrowAsJavaScriptException();
        return;
    }
}

Napi::Value NftManager::CreateTable(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::make_unique<CreateTableOp>(config_), std::move(deferred));
    return promise;
}

Napi::Value NftManager::AddAddress(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "addAddress requires an options object: { ip, set, timeout? }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Object opts = info[0].As<Napi::Object>();

    // ip — required string
    if (!opts.Has("ip") || !opts.Get("ip").IsString()) {
        Napi::TypeError::New(env, "addAddress: 'ip' is required and must be a string")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string ip = opts.Get("ip").As<Napi::String>().Utf8Value();

    // set — required string
    auto set_idx = parse_set_name(env, opts, "addAddress", *config_);
    if (!set_idx) return env.Undefined();

    // timeout — optional number (seconds). If absent, 0 = permanent
    auto timeout_ms = parse_timeout(env, opts, "addAddress");
    if (!timeout_ms) return env.Undefined();

    // Validate IP
    IpAddr addr = parse_ip(ip);
    if (addr.family == IpFamily::Invalid) {
        Napi::Error::New(env, "Invalid IP address: " + ip)
            .ThrowAsJavaScriptException();
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

    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "removeAddress requires an options object: { ip, set }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Object opts = info[0].As<Napi::Object>();

    // ip — required string
    if (!opts.Has("ip") || !opts.Get("ip").IsString()) {
        Napi::TypeError::New(env, "removeAddress: 'ip' is required and must be a string")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string ip = opts.Get("ip").As<Napi::String>().Utf8Value();

    // set — required string
    auto set_idx = parse_set_name(env, opts, "removeAddress", *config_);
    if (!set_idx) return env.Undefined();

    // Validate IP
    IpAddr addr = parse_ip(ip);
    if (addr.family == IpFamily::Invalid) {
        Napi::Error::New(env, "Invalid IP address: " + ip)
            .ThrowAsJavaScriptException();
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

    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "addAddresses requires an options object: { ips, set, timeout? }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Object opts = info[0].As<Napi::Object>();

    // ips — required Array of strings
    if (!opts.Has("ips") || !opts.Get("ips").IsArray()) {
        Napi::TypeError::New(env, "addAddresses: 'ips' is required and must be an array of strings")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Array arr = opts.Get("ips").As<Napi::Array>();

    // set — required string
    auto set_idx = parse_set_name(env, opts, "addAddresses", *config_);
    if (!set_idx) return env.Undefined();

    // timeout — optional number (seconds). If absent, 0 = permanent
    auto timeout_ms = parse_timeout(env, opts, "addAddresses");
    if (!timeout_ms) return env.Undefined();

    std::vector<ParsedAddr> addrs = parse_ip_array(env, arr);
    if (env.IsExceptionPending()) return env.Undefined();

    // Empty arrays: early-exit with resolved promise
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

    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "removeAddresses requires an options object: { ips, set }")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Object opts = info[0].As<Napi::Object>();

    // ips — required Array of strings
    if (!opts.Has("ips") || !opts.Get("ips").IsArray()) {
        Napi::TypeError::New(env, "removeAddresses: 'ips' is required and must be an array of strings")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Array arr = opts.Get("ips").As<Napi::Array>();

    // set — required string
    auto set_idx = parse_set_name(env, opts, "removeAddresses", *config_);
    if (!set_idx) return env.Undefined();

    std::vector<ParsedAddr> addrs = parse_ip_array(env, arr);
    if (env.IsExceptionPending()) return env.Undefined();

    // Empty arrays: early-exit with resolved promise
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

Napi::Value NftManager::DeleteTable(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::make_unique<DeleteTableOp>(config_), std::move(deferred));
    return promise;
}

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
