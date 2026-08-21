import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';

export const ZIG_VERSION = '0.16.0';

// https://ziglang.org/download/index.json
const ZIG_SHA256 = {
    'darwin-arm64': [
        'zig-aarch64-macos',
        'b23d70deaa879b5c2d486ed3316f7eaa53e84acf6fc9cc747de152450d401489',
    ],
    'darwin-x64': [
        'zig-x86_64-macos',
        '0387557ed1877bc6a2e1802c8391953baddba76081876301c522f52977b52ba7',
    ],
    'linux-arm64': [
        'zig-aarch64-linux',
        'ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17',
    ],
    'linux-x64': [
        'zig-x86_64-linux',
        '70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00',
    ],
};

export const ROOT = path.resolve(import.meta.dirname, '..');
export const CACHE = path.join(ROOT, '.cache');

const exists = (p) =>
    fs
        .stat(p)
        .then(() => true)
        .catch(() => false);

export function run(cmd, args, opts = {}) {
    const { quiet = false, ...spawnOpts } = opts;
    const capture = quiet && !process.env.VERBOSE;

    return new Promise((resolve, reject) => {
        const child = spawn(cmd, args, {
            stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
            ...spawnOpts,
        });

        let tail = '';
        if (capture) {
            const keep = (chunk) => {
                tail = (tail + chunk).slice(-8000);
            };
            child.stdout.on('data', keep);
            child.stderr.on('data', keep);
        }

        child.on('error', reject);
        child.on('exit', (code) => {
            if (code === 0) return resolve();
            if (tail) process.stderr.write(`\n${tail}\n`);
            reject(new Error(`${path.basename(cmd)} ${args.join(' ')} exited with ${code}`));
        });
    });
}

export async function download(url, dest, sha256) {
    if (await exists(dest)) {
        const have = createHash('sha256')
            .update(await fs.readFile(dest))
            .digest('hex');
        if (have === sha256) return dest;
        await fs.rm(dest);
    }
    process.stderr.write(`  fetching ${url}\n`);
    const res = await fetch(url, { redirect: 'follow' });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);

    await fs.mkdir(path.dirname(dest), { recursive: true });
    const tmp = `${dest}.part`;
    const hash = createHash('sha256');
    await pipeline(
        res.body,
        async function* (chunks) {
            for await (const c of chunks) {
                hash.update(c);
                yield c;
            }
        },
        (await fs.open(tmp, 'w')).createWriteStream(),
    );

    const got = hash.digest('hex');
    if (got !== sha256) {
        await fs.rm(tmp, { force: true });
        throw new Error(`checksum mismatch for ${url}\n  expected ${sha256}\n  got      ${got}`);
    }
    await fs.rename(tmp, dest);
    return dest;
}

export async function ensureZig() {
    if (process.env.ZIG) return process.env.ZIG;

    const key = `${os.platform()}-${os.arch()}`;
    const entry = ZIG_SHA256[key];
    if (!entry) throw new Error(`no pinned Zig build for ${key} — set ZIG=/path/to/zig`);
    const [stem, sha256] = entry;

    const dir = path.join(CACHE, 'zig', ZIG_VERSION);
    const bin = path.join(dir, 'zig');
    if (await exists(bin)) return bin;

    const name = `${stem}-${ZIG_VERSION}.tar.xz`;
    const archive = await download(
        `https://ziglang.org/download/${ZIG_VERSION}/${name}`,
        path.join(CACHE, 'downloads', name),
        sha256,
    );

    await fs.mkdir(dir, { recursive: true });
    await run('tar', ['-xJf', archive, '--strip-components=1', '-C', dir]);
    return bin;
}
