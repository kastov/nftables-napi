export const GLIBC = '2.28';

export const TARGETS = [
    {
        name: 'linux-x64-glibc',
        zig: `x86_64-linux-gnu.${GLIBC}`,
        host: 'x86_64-linux-gnu',
        dir: 'linux-x64',
        file: 'nftables-napi.glibc.node',
    },
    {
        name: 'linux-x64-musl',
        zig: 'x86_64-linux-musl',
        host: 'x86_64-linux-musl',
        dir: 'linux-x64',
        file: 'nftables-napi.musl.node',
    },
    {
        name: 'linux-arm64-glibc',
        zig: `aarch64-linux-gnu.${GLIBC}`,
        host: 'aarch64-linux-gnu',
        dir: 'linux-arm64',
        file: 'nftables-napi.glibc.node',
    },
    {
        name: 'linux-arm64-musl',
        zig: 'aarch64-linux-musl',
        host: 'aarch64-linux-musl',
        dir: 'linux-arm64',
        file: 'nftables-napi.musl.node',
    },
];

export function selectTargets(filter) {
    if (!filter || filter.length === 0) return TARGETS;
    const picked = TARGETS.filter((t) => filter.some((f) => t.name.includes(f)));
    if (picked.length === 0) {
        throw new Error(`no target matches ${filter.join(', ')}`);
    }
    return picked;
}
