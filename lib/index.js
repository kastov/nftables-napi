'use strict';

const path = require('path');

const MIN_NODE_MAJOR = 24;

function candidates() {
    if (process.platform !== 'linux') return [];

    const dir = path.join(__dirname, '..', 'prebuilds', `linux-${process.arch}`);

    let glibc = false;
    try {
        glibc = Boolean(process.report.getReport().header.glibcVersionRuntime);
    } catch {
        // silence
    }

    return (glibc ? ['glibc', 'musl'] : ['musl', 'glibc']).map((libc) =>
        path.join(dir, `nftables-napi.${libc}.node`),
    );
}

function nodeTooOld() {
    const major = Number.parseInt(process.versions.node, 10);
    return Number.isFinite(major) && major < MIN_NODE_MAJOR;
}

function load() {
    if (nodeTooOld()) return null;

    if (process.env.NFTABLES_NAPI_BINDING) {
        return require(path.resolve(process.env.NFTABLES_NAPI_BINDING));
    }

    const errors = [];
    for (const candidate of candidates()) {
        try {
            return require(candidate);
        } catch (err) {
            errors.push(`  ${candidate}: ${err.message}`);
        }
    }
    return errors;
}

const loaded = load();
const binding = loaded === null || Array.isArray(loaded) ? null : loaded;

module.exports = binding || {
    NftManager: class {
        constructor() {
            if (nodeTooOld()) {
                throw new Error(
                    `nftables-napi requires Node.js >= ${MIN_NODE_MAJOR} (it uses Node-API v10); ` +
                        `this is Node ${process.versions.node}.`,
                );
            }
            throw new Error(
                'nftables-napi has no prebuilt binary for this environment. ' +
                    'It supports Linux x64/arm64 on glibc >= 2.28 or musl; this is ' +
                    `${process.platform}-${process.arch}.` +
                    (loaded && loaded.length ? `\nTried:\n${loaded.join('\n')}` : ''),
            );
        }
    },
};
