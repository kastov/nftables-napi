'use strict';

const path = require('path');

let binding = null;
try {
    binding = require('node-gyp-build')(path.join(__dirname, '..'));
} catch {
    // Non-Linux, or no compatible prebuild and no build toolchain available.
}

module.exports = binding || {
    NftManager: class {
        constructor() {
            throw new Error(
                'nftables-napi only works on Linux with CAP_NET_ADMIN. Native binding failed to load.',
            );
        }
    },
};
