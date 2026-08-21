#if !defined(NAPI_VERSION) || NAPI_VERSION < 10
#error "nftables-napi requires Node-API v10 (Node.js >= 24). Build with -DNAPI_VERSION=10."
#endif

#include <napi.h>
#include "nft_manager.h"

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    NftManager::Init(env, exports);
    return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
