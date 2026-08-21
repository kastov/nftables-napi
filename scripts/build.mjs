import fs from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

import { buildDeps } from './build-deps.mjs';
import { selectTargets } from './targets.mjs';
import { ROOT, ensureZig, run } from './zig.mjs';

const require = createRequire(import.meta.url);

const NAPI_VERSION = 10;

async function sources(dir) {
    const out = [];
    for (const entry of await fs.readdir(dir, { withFileTypes: true, recursive: true })) {
        if (entry.isFile() && entry.name.endsWith('.cpp')) {
            out.push(path.relative(ROOT, path.join(entry.parentPath, entry.name)));
        }
    }
    return out.sort();
}

async function buildOne(target, zig, srcs) {
    const deps = path.join(ROOT, '.deps', target.name);
    const output = path.join(ROOT, 'prebuilds', target.dir, target.file);
    await fs.mkdir(path.dirname(output), { recursive: true });

    const args = [
        'c++',
        '-target',
        target.zig,
        '-mcpu=baseline',
        '-shared',
        '-fPIC',
        '-O3',
        '-std=c++20',
        '-fno-exceptions',
        '-fno-rtti',
        '-fvisibility=hidden',
        '-fvisibility-inlines-hidden',
        '-ffunction-sections',
        '-fdata-sections',
        '-fstack-protector-strong',
        '-Wall',
        '-Wextra',
        '-Wpedantic',
        '-Wno-unused-parameter',
        `-DNAPI_VERSION=${NAPI_VERSION}`,
        '-DNAPI_DISABLE_CPP_EXCEPTIONS',
        '-DNODE_GYP_MODULE_NAME=nftables_napi',
        `-I${require('node-api-headers').include_dir}`,
        `-I${require('node-addon-api').include_dir}`,
        `-I${path.join(deps, 'include')}`,
        '-Wl,-z,relro',
        '-Wl,-z,now',
        '-Wl,-z,noexecstack',
        '-Wl,--gc-sections',
        '-Wl,-s',
        '-o',
        output,
        ...srcs,
        path.join(deps, 'lib', 'libnftnl.a'),
        path.join(deps, 'lib', 'libmnl.a'),
    ];

    process.stderr.write(`\nbuild ${target.name}: ${target.zig}\n`);
    await run(zig, args, { cwd: ROOT });

    const { size } = await fs.stat(output);
    process.stderr.write(
        `build ${target.name}: ${path.relative(ROOT, output)} (${Math.round(size / 1024)} KiB)\n`,
    );
}

const targets = selectTargets(process.argv.slice(2));
await buildDeps(targets);
const zig = await ensureZig();
const srcs = await sources(path.join(ROOT, 'src'));
for (const target of targets) {
    await buildOne(target, zig, srcs);
}
