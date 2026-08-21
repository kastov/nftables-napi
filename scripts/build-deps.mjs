import fs from 'node:fs/promises';
import path from 'node:path';

import { selectTargets } from './targets.mjs';
import { ROOT, CACHE, ZIG_VERSION, ensureZig, download, run } from './zig.mjs';

const PACKAGES = [
    {
        name: 'libmnl',
        version: '1.0.5',
        archive: 'libmnl-1.0.5.tar.bz2',
        url: 'https://www.netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2',
        sha256: '274b9b919ef3152bfb3da3a13c950dd60d6e2bcd54230ffeca298d03b40d0525',
        tarFlag: '-xjf',
    },
    {
        name: 'libnftnl',
        version: '1.3.1',
        archive: 'libnftnl-1.3.1.tar.xz',
        url: 'https://www.netfilter.org/projects/libnftnl/files/libnftnl-1.3.1.tar.xz',
        sha256: '607da28dba66fbdeccf8ef1395dded9077e8d19f2995f9a4d45a9c2f0bcffba8',
        tarFlag: '-xJf',
    },
];

const exists = (p) =>
    fs
        .stat(p)
        .then(() => true)
        .catch(() => false);

async function writeToolchain(dir, zig, triple) {
    await fs.mkdir(dir, { recursive: true });

    const base = triple.replace(/\.\d+(\.\d+)*$/, '');

    const shims = {
        cc: `#!/bin/sh\nexec "${zig}" cc -target ${base} -mcpu=baseline "$@"\n`,
        ar: `#!/bin/sh\nexec "${zig}" ar "$@"\n`,
        ranlib: `#!/bin/sh\nexec "${zig}" ranlib "$@"\n`,
    };
    for (const [name, body] of Object.entries(shims)) {
        const p = path.join(dir, name);
        await fs.writeFile(p, body);
        await fs.chmod(p, 0o755);
    }
    return shims;
}

async function buildPackage(pkg, target, zig, prefix) {
    const work = path.join(CACHE, 'build', target.name);
    const srcDir = path.join(work, `${pkg.name}-${pkg.version}`);
    const bin = path.join(work, 'toolchain');

    await fs.mkdir(work, { recursive: true });
    await fs.rm(srcDir, { recursive: true, force: true });

    const archive = await download(pkg.url, path.join(CACHE, 'downloads', pkg.archive), pkg.sha256);
    await run('tar', [pkg.tarFlag, archive, '-C', work], { quiet: true });

    const env = {
        ...process.env,
        CC: path.join(bin, 'cc'),
        AR: path.join(bin, 'ar'),
        RANLIB: path.join(bin, 'ranlib'),
        CFLAGS: '-O2 -fPIC -fno-strict-aliasing',
        LIBMNL_CFLAGS: `-I${path.join(prefix, 'include')}`,
        LIBMNL_LIBS: `-L${path.join(prefix, 'lib')} -lmnl`,
    };

    process.stderr.write(`  ${pkg.name} ${pkg.version}: configure\n`);
    await run(
        './configure',
        [
            `--host=${target.host}`,
            `--prefix=${prefix}`,
            '--enable-static',
            '--disable-shared',
            '--disable-dependency-tracking',
            '--enable-silent-rules',
        ],
        { cwd: srcDir, env, quiet: true },
    );

    process.stderr.write(`  ${pkg.name} ${pkg.version}: make + install\n`);
    for (const sub of ['src', 'include']) {
        await run('make', ['-j', String(4), '-C', sub], { cwd: srcDir, env, quiet: true });
        await run('make', ['-C', sub, 'install'], { cwd: srcDir, env, quiet: true });
    }
}

export async function buildDeps(targets) {
    const zig = await ensureZig();
    for (const target of targets) {
        const prefix = path.join(ROOT, '.deps', target.name);
        const key = [ZIG_VERSION, ...PACKAGES.map((p) => p.version)].join('-');
        const stamp = path.join(prefix, `.stamp-${key}`);
        if (await exists(stamp)) {
            process.stderr.write(`deps ${target.name}: up to date\n`);
            continue;
        }

        process.stderr.write(`\ndeps ${target.name}: building for ${target.zig}\n`);
        await fs.rm(prefix, { recursive: true, force: true });
        await writeToolchain(path.join(CACHE, 'build', target.name, 'toolchain'), zig, target.zig);

        for (const pkg of PACKAGES) {
            await buildPackage(pkg, target, zig, prefix);
        }
        await fs.writeFile(stamp, '');
    }
}

if (import.meta.filename === process.argv[1]) {
    await buildDeps(selectTargets(process.argv.slice(2)));
}
