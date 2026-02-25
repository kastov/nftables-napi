#include <napi.h>
#include "nft_manager.h"

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    NftManager::Init(env, exports);
    return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
