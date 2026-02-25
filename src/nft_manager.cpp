#include "nft_manager.h"
#include "validation.h"
#include "workers/nft_worker.h"
#include "netlink/parsed_addr.h"
#include "netlink/table_ops.h"
#include "netlink/set_ops.h"

#include <cstring>
#include <vector>

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

    // 1. Validate options object exists
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env,
            "NftManager requires options object with tableName, blacklistSetName, droplistSetName")
            .ThrowAsJavaScriptException();
        return;
    }

    Napi::Object opts = info[0].As<Napi::Object>();

    // 2. Extract and validate 3 required string fields
    if (!opts.Has("tableName") || !opts.Get("tableName").IsString()) {
        Napi::TypeError::New(env, "NftManager: 'tableName' is required and must be a string")
            .ThrowAsJavaScriptException();
        return;
    }
    if (!opts.Has("blacklistSetName") || !opts.Get("blacklistSetName").IsString()) {
        Napi::TypeError::New(env, "NftManager: 'blacklistSetName' is required and must be a string")
            .ThrowAsJavaScriptException();
        return;
    }
    if (!opts.Has("droplistSetName") || !opts.Get("droplistSetName").IsString()) {
        Napi::TypeError::New(env, "NftManager: 'droplistSetName' is required and must be a string")
            .ThrowAsJavaScriptException();
        return;
    }

    std::string table_name = opts.Get("tableName").As<Napi::String>().Utf8Value();
    std::string blacklist_set_name = opts.Get("blacklistSetName").As<Napi::String>().Utf8Value();
    std::string droplist_set_name = opts.Get("droplistSetName").As<Napi::String>().Utf8Value();

    // 3. Create NftConfig from names
    config_ = std::make_shared<const nft::NftConfig>(
        nft::NftConfig::from_names(table_name, blacklist_set_name, droplist_set_name));

    // 4. Open netlink socket
    sock_ = std::make_shared<NlSocket>();

    // 5. Validate socket
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

    // set — required string ('blacklist' or 'droplist')
    if (!opts.Has("set") || !opts.Get("set").IsString()) {
        Napi::TypeError::New(env, "addAddress: 'set' is required and must be a string ('blacklist' or 'droplist')")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string set_str = opts.Get("set").As<Napi::String>().Utf8Value();
    nft::TargetSet target = nft::TargetSet::Blacklist;
    if (set_str == "blacklist") {
        target = nft::TargetSet::Blacklist;
    } else if (set_str == "droplist") {
        target = nft::TargetSet::Droplist;
    } else {
        Napi::Error::New(env, "addAddress: 'set' must be 'blacklist' or 'droplist'")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // timeout — optional number (seconds). If absent, 0 = permanent
    uint64_t timeout_ms = 0;
    if (opts.Has("timeout") && !opts.Get("timeout").IsUndefined() && !opts.Get("timeout").IsNull()) {
        Napi::Value tv = opts.Get("timeout");
        if (!tv.IsNumber()) {
            Napi::TypeError::New(env, "addAddress: 'timeout' must be a number (seconds)")
                .ThrowAsJavaScriptException();
            return env.Undefined();
        }
        double timeout_sec = tv.As<Napi::Number>().DoubleValue();
        if (timeout_sec <= 0 || timeout_sec > 4294967295.0) {
            Napi::Error::New(env, "addAddress: 'timeout' must be a positive number (seconds)")
                .ThrowAsJavaScriptException();
            return env.Undefined();
        }
        timeout_ms = static_cast<uint64_t>(timeout_sec) * 1000;
    }

    // Validate IP
    IpAddr addr = parse_ip(ip);
    if (addr.family == IpFamily::Invalid) {
        Napi::Error::New(env, "Invalid IP address: " + ip)
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::vector<ParsedAddr> addrs;
    addrs.push_back(to_parsed_addr(addr));
    auto op = std::make_unique<BulkAddSetElemOp>(std::move(addrs), timeout_ms, config_, target);

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

    // set — required string ('blacklist' or 'droplist')
    if (!opts.Has("set") || !opts.Get("set").IsString()) {
        Napi::TypeError::New(env, "removeAddress: 'set' is required and must be a string ('blacklist' or 'droplist')")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string set_str = opts.Get("set").As<Napi::String>().Utf8Value();
    nft::TargetSet target = nft::TargetSet::Blacklist;
    if (set_str == "blacklist") {
        target = nft::TargetSet::Blacklist;
    } else if (set_str == "droplist") {
        target = nft::TargetSet::Droplist;
    } else {
        Napi::Error::New(env, "removeAddress: 'set' must be 'blacklist' or 'droplist'")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Validate IP
    IpAddr addr = parse_ip(ip);
    if (addr.family == IpFamily::Invalid) {
        Napi::Error::New(env, "Invalid IP address: " + ip)
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::vector<ParsedAddr> addrs;
    addrs.push_back(to_parsed_addr(addr));
    auto op = std::make_unique<BulkDelSetElemOp>(std::move(addrs), config_, target);

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

    // set — required string ('blacklist' or 'droplist')
    if (!opts.Has("set") || !opts.Get("set").IsString()) {
        Napi::TypeError::New(env, "addAddresses: 'set' is required and must be a string ('blacklist' or 'droplist')")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string set_str = opts.Get("set").As<Napi::String>().Utf8Value();
    nft::TargetSet target = nft::TargetSet::Blacklist;
    if (set_str == "blacklist") {
        target = nft::TargetSet::Blacklist;
    } else if (set_str == "droplist") {
        target = nft::TargetSet::Droplist;
    } else {
        Napi::Error::New(env, "addAddresses: 'set' must be 'blacklist' or 'droplist'")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // timeout — optional number (seconds). If absent, 0 = permanent
    uint64_t timeout_ms = 0;
    if (opts.Has("timeout") && !opts.Get("timeout").IsUndefined() && !opts.Get("timeout").IsNull()) {
        Napi::Value tv = opts.Get("timeout");
        if (!tv.IsNumber()) {
            Napi::TypeError::New(env, "addAddresses: 'timeout' must be a number (seconds)")
                .ThrowAsJavaScriptException();
            return env.Undefined();
        }
        double timeout_sec = tv.As<Napi::Number>().DoubleValue();
        if (timeout_sec <= 0 || timeout_sec > 4294967295.0) {
            Napi::Error::New(env, "addAddresses: 'timeout' must be a positive number (seconds)")
                .ThrowAsJavaScriptException();
            return env.Undefined();
        }
        timeout_ms = static_cast<uint64_t>(timeout_sec) * 1000;
    }

    std::vector<ParsedAddr> addrs = parse_ip_array(env, arr);
    if (env.IsExceptionPending()) return env.Undefined();

    // Empty arrays: early-exit with resolved promise
    if (addrs.empty()) {
        auto deferred = Napi::Promise::Deferred::New(env);
        auto promise = deferred.Promise();
        deferred.Resolve(env.Undefined());
        return promise;
    }

    auto op = std::make_unique<BulkAddSetElemOp>(std::move(addrs), timeout_ms, config_, target);

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

    // set — required string ('blacklist' or 'droplist')
    if (!opts.Has("set") || !opts.Get("set").IsString()) {
        Napi::TypeError::New(env, "removeAddresses: 'set' is required and must be a string ('blacklist' or 'droplist')")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string set_str = opts.Get("set").As<Napi::String>().Utf8Value();
    nft::TargetSet target = nft::TargetSet::Blacklist;
    if (set_str == "blacklist") {
        target = nft::TargetSet::Blacklist;
    } else if (set_str == "droplist") {
        target = nft::TargetSet::Droplist;
    } else {
        Napi::Error::New(env, "removeAddresses: 'set' must be 'blacklist' or 'droplist'")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::vector<ParsedAddr> addrs = parse_ip_array(env, arr);
    if (env.IsExceptionPending()) return env.Undefined();

    // Empty arrays: early-exit with resolved promise
    if (addrs.empty()) {
        auto deferred = Napi::Promise::Deferred::New(env);
        auto promise = deferred.Promise();
        deferred.Resolve(env.Undefined());
        return promise;
    }

    auto op = std::make_unique<BulkDelSetElemOp>(std::move(addrs), config_, target);

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
