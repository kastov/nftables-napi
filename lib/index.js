'use strict';

const path = require('path');

let binding;
try {
  binding = require('node-gyp-build')(path.join(__dirname, '..'));
} catch (e) {
  // On non-Linux platforms, the native addon may fail to load
  binding = null;
}

if (binding) {
  module.exports = binding;
} else {
  class NftManager {
    constructor() {
      throw new Error(
        'remnawave-nft only works on Linux with CAP_NET_ADMIN. Native binding failed to load.'
      );
    }
  }
  module.exports = { NftManager };
}
