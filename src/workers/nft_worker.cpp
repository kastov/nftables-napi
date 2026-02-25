#include "nft_worker.h"
#include "../nft_manager.h"

NftWorker::NftWorker(Napi::Env env,
                     std::shared_ptr<NlSocket> sock,
                     std::unique_ptr<NlOperation> op,
                     Napi::Promise::Deferred deferred,
                     NftManager* owner)
    : Napi::AsyncWorker(env, "NftWorker"),
      deferred_(std::move(deferred)),
      sock_(std::move(sock)),
      op_(std::move(op)),
      owner_(owner) {}

void NftWorker::Execute() {
    NlResult result = op_->execute(*sock_);
    if (!result.success) {
        SetError(result.error);
    }
}

void NftWorker::OnOK() {
    deferred_.Resolve(Env().Undefined());
    owner_->OnWorkerDone();
}

void NftWorker::OnError(const Napi::Error& e) {
    deferred_.Reject(e.Value());
    owner_->OnWorkerDone();
}
