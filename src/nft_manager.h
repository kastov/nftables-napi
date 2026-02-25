#pragma once

#include <napi.h>
#include <memory>
#include <queue>

#include "netlink/nl_socket.h"
#include "netlink/operation.h"
#include "netlink/nft_config.h"

struct PendingOp {
    std::unique_ptr<NlOperation> op;
    Napi::Promise::Deferred deferred;
};

class NftManager : public Napi::ObjectWrap<NftManager> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    NftManager(const Napi::CallbackInfo& info);
    ~NftManager() override = default;

    // Called by NftWorker when async work completes
    void OnWorkerDone();

private:
    Napi::Value CreateTable(const Napi::CallbackInfo& info);
    Napi::Value AddAddress(const Napi::CallbackInfo& info);
    Napi::Value RemoveAddress(const Napi::CallbackInfo& info);
    Napi::Value AddAddresses(const Napi::CallbackInfo& info);
    Napi::Value RemoveAddresses(const Napi::CallbackInfo& info);
    Napi::Value DeleteTable(const Napi::CallbackInfo& info);

    void Enqueue(std::unique_ptr<NlOperation> op, Napi::Promise::Deferred deferred);
    void DrainQueue();

    // Thread safety: sock_ is accessed from worker threads in Execute(), but
    // worker_active_ ensures only one NftWorker runs at a time. All queue
    // management (Enqueue, DrainQueue, OnWorkerDone) runs on the JS main thread.
    // This invariant MUST be preserved if refactoring the queue.
    std::shared_ptr<NlSocket> sock_;
    std::shared_ptr<const nft::NftConfig> config_;
    std::queue<PendingOp> queue_;
    bool worker_active_ = false;
};
