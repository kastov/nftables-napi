#pragma once

#include <napi.h>
#include <memory>

#include "../netlink/operation.h"
#include "../netlink/nl_socket.h"

// Forward declaration — NftManager calls OnWorkerDone() from OnOK/OnError
class NftManager;

class NftWorker : public Napi::AsyncWorker {
public:
    NftWorker(Napi::Env env,
              std::shared_ptr<NlSocket> sock,
              std::unique_ptr<NlOperation> op,
              Napi::Promise::Deferred deferred,
              NftManager* owner);

protected:
    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& e) override;

private:
    Napi::Promise::Deferred deferred_;
    std::shared_ptr<NlSocket> sock_;
    std::unique_ptr<NlOperation> op_;
    NftManager* owner_;
};
