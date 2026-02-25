#include "nft_manager.h"
#include "validation.h"
#include "workers/nft_worker.h"

#include <cstring>
#include <vector>

extern "C" {
#include <linux/netfilter.h>
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

        ParsedAddr pa{};
        pa.family = (addr.family == IpFamily::IPv4) ? NFPROTO_IPV4 : NFPROTO_IPV6;
        pa.len = addr.len;
        std::memcpy(pa.bytes, addr.bytes.data(), addr.len);
        addrs.push_back(pa);
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

    if (info.Length() >= 1 && info[0].IsObject()) {
        Napi::Object opts = info[0].As<Napi::Object>();
        if (opts.Has("strategy")) {
            Napi::Value val = opts.Get("strategy");
            if (!val.IsString()) {
                Napi::TypeError::New(env, "strategy must be a string")
                    .ThrowAsJavaScriptException();
                return;
            }
            std::string s = val.As<Napi::String>().Utf8Value();
            if (s == "drop") {
                strategy_ = nft::FirewallStrategy::Drop;
            } else if (s == "reject") {
                strategy_ = nft::FirewallStrategy::Reject;
            } else if (s == "tcp-reset") {
                strategy_ = nft::FirewallStrategy::TcpReset;
            } else {
                Napi::Error::New(env, "Invalid strategy: '" + s + "'. Must be 'drop', 'reject', or 'tcp-reset'")
                    .ThrowAsJavaScriptException();
                return;
            }
        }
    }

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
    Enqueue(std::make_unique<CreateTableOp>(strategy_), std::move(deferred));
    return promise;
}

Napi::Value NftManager::AddAddress(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "addAddress requires two string arguments: ip and timeout")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string ip = info[0].As<Napi::String>().Utf8Value();
    std::string timeout = info[1].As<Napi::String>().Utf8Value();

    IpAddr addr = parse_ip(ip);
    if (addr.family == IpFamily::Invalid) {
        Napi::Error::New(env, "Invalid IP address")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    uint64_t timeout_ms = parse_timeout_ms(timeout);
    if (timeout_ms == 0) {
        Napi::Error::New(env, "Invalid timeout value")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    ParsedAddr pa{};
    pa.family = (addr.family == IpFamily::IPv4) ? NFPROTO_IPV4 : NFPROTO_IPV6;
    pa.len = addr.len;
    std::memcpy(pa.bytes, addr.bytes.data(), addr.len);

    std::vector<ParsedAddr> addrs;
    addrs.push_back(pa);
    auto op = std::make_unique<BulkAddSetElemOp>(std::move(addrs), timeout_ms);

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::RemoveAddress(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "removeAddress requires a string argument: ip")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string ip = info[0].As<Napi::String>().Utf8Value();

    IpAddr addr = parse_ip(ip);
    if (addr.family == IpFamily::Invalid) {
        Napi::Error::New(env, "Invalid IP address")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    ParsedAddr pa{};
    pa.family = (addr.family == IpFamily::IPv4) ? NFPROTO_IPV4 : NFPROTO_IPV6;
    pa.len = addr.len;
    std::memcpy(pa.bytes, addr.bytes.data(), addr.len);

    std::vector<ParsedAddr> addrs;
    addrs.push_back(pa);
    auto op = std::make_unique<BulkDelSetElemOp>(std::move(addrs));

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::AddAddresses(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsArray() || !info[1].IsString()) {
        Napi::TypeError::New(env, "addAddresses requires an array of IPs and a timeout string")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Array arr = info[0].As<Napi::Array>();
    std::string timeout = info[1].As<Napi::String>().Utf8Value();

    uint64_t timeout_ms = parse_timeout_ms(timeout);
    if (timeout_ms == 0) {
        Napi::Error::New(env, "Invalid timeout value")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::vector<ParsedAddr> addrs = parse_ip_array(env, arr);
    if (env.IsExceptionPending()) return env.Undefined();

    if (addrs.empty()) {
        auto deferred = Napi::Promise::Deferred::New(env);
        auto promise = deferred.Promise();
        deferred.Resolve(env.Undefined());
        return promise;
    }

    auto op = std::make_unique<BulkAddSetElemOp>(std::move(addrs), timeout_ms);

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::RemoveAddresses(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsArray()) {
        Napi::TypeError::New(env, "removeAddresses requires an array of IPs")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Array arr = info[0].As<Napi::Array>();

    std::vector<ParsedAddr> addrs = parse_ip_array(env, arr);
    if (env.IsExceptionPending()) return env.Undefined();

    if (addrs.empty()) {
        auto deferred = Napi::Promise::Deferred::New(env);
        auto promise = deferred.Promise();
        deferred.Resolve(env.Undefined());
        return promise;
    }

    auto op = std::make_unique<BulkDelSetElemOp>(std::move(addrs));

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::move(op), std::move(deferred));
    return promise;
}

Napi::Value NftManager::DeleteTable(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    auto deferred = Napi::Promise::Deferred::New(env);
    auto promise = deferred.Promise();
    Enqueue(std::make_unique<DeleteTableOp>(), std::move(deferred));
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
