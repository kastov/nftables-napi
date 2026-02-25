import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { NftManager } = require('../lib/index.js');

// Check if we can create context (need CAP_NET_ADMIN)
let canCreateContext = false;
let nft;
try {
    nft = new NftManager();
    canCreateContext = true;
} catch {
    // No root/CAP_NET_ADMIN — integration tests will be skipped
}

describe('NftManager validation', () => {
    // These tests verify synchronous argument validation.
    // They may still need a valid context, so skip if no CAP_NET_ADMIN.

    it('should export NftManager as a function/class', () => {
        assert.equal(typeof NftManager, 'function');
    });

    it('should throw on addAddress with no arguments', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddress(), { name: 'TypeError' });
    });

    it('should throw on addAddress with one argument', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddress('1.2.3.4'), { name: 'TypeError' });
    });

    it('should throw on addAddress with non-string ip', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddress(123, '10m'), { name: 'TypeError' });
    });

    it('should throw on addAddress with non-string timeout', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddress('1.2.3.4', 42), { name: 'TypeError' });
    });

    it('should throw on addAddress with invalid IP', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddress('not-an-ip', '10m'));
    });

    it('should throw on addAddress with invalid timeout', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddress('1.2.3.4', 'bad'));
    });

    it('should throw on removeAddress with no arguments', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.removeAddress(), { name: 'TypeError' });
    });

    it('should throw on removeAddress with non-string', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.removeAddress(42), { name: 'TypeError' });
    });

    it('should throw on removeAddress with invalid IP', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.removeAddress('invalid'));
    });

    it('should throw on addAddresses with non-array', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddresses('not-array', '10m'), { name: 'TypeError' });
    });

    it('should throw on addAddresses with non-string element', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddresses([123], '10m'), { name: 'TypeError' });
    });

    it('should throw on addAddresses with invalid IP in array', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddresses(['1.2.3.4', 'invalid'], '10m'));
    });

    it('should throw on addAddresses with invalid timeout', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.addAddresses(['1.2.3.4'], 'bad'));
    });

    it('should throw on removeAddresses with non-array', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.removeAddresses('not-array'), { name: 'TypeError' });
    });

    it('should throw on removeAddresses with invalid IP', { skip: !canCreateContext }, () => {
        assert.throws(() => nft.removeAddresses(['invalid']), { name: 'Error' });
    });

    it('should accept empty options object', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({});
        assert.ok(mgr);
    });

    it('should accept strategy "drop"', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ strategy: 'drop' });
        assert.ok(mgr);
    });

    it('should accept strategy "reject"', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ strategy: 'reject' });
        assert.ok(mgr);
    });

    it('should accept strategy "tcp-reset"', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ strategy: 'tcp-reset' });
        assert.ok(mgr);
    });

    it('should throw on invalid strategy value', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ strategy: 'invalid' }), { name: 'Error' });
    });

    it('should throw on non-string strategy', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ strategy: 42 }), { name: 'TypeError' });
    });
});

describe('NftManager integration', { skip: !canCreateContext }, () => {
    after(async () => {
        // Cleanup
        try { await nft.deleteTable(); } catch { /* ignore */ }
    });

    it('should create tables', async () => {
        await nft.createTable();
    });

    it('should create tables idempotently (second call)', async () => {
        await nft.createTable();
    });

    it('should add IPv4 address to blacklist', async () => {
        await nft.addAddress('192.168.99.99', '1m');
    });

    it('should add IPv6 address to blacklist', async () => {
        await nft.addAddress('2001:db8::dead:beef', '2m');
    });

    it('should add another IPv4 with different timeout unit', async () => {
        await nft.addAddress('10.0.0.1', '30s');
    });

    it('should remove IPv4 address', async () => {
        await nft.removeAddress('192.168.99.99');
    });

    it('should remove IPv6 address', async () => {
        await nft.removeAddress('2001:db8::dead:beef');
    });

    it('should remove non-existent address idempotently', async () => {
        await nft.removeAddress('172.16.0.1');
    });

    it('should bulk add IPv4 and IPv6 addresses', async () => {
        await nft.addAddresses([
            '10.0.0.10', '10.0.0.11', '10.0.0.12',
            '2001:db8::10', '2001:db8::11'
        ], '5m');
    });

    it('should bulk remove addresses', async () => {
        await nft.removeAddresses([
            '10.0.0.10', '10.0.0.11', '10.0.0.12',
            '2001:db8::10', '2001:db8::11'
        ]);
    });

    it('should bulk remove non-existent addresses idempotently', async () => {
        await nft.removeAddresses(['172.16.0.100', '172.16.0.101']);
    });

    it('should handle empty arrays as no-op', async () => {
        await nft.addAddresses([], '1m');
        await nft.removeAddresses([]);
    });

    it('should delete tables', async () => {
        await nft.deleteTable();
    });

    it('should delete tables idempotently', async () => {
        await nft.deleteTable();
    });
});

describe('NftManager drop strategy', { skip: !canCreateContext }, () => {
    let nftDrop;

    after(async () => {
        try { if (nftDrop) await nftDrop.deleteTable(); } catch { /* ignore */ }
    });

    it('should create tables with drop strategy', async () => {
        nftDrop = new NftManager({ strategy: 'drop' });
        await nftDrop.createTable();
    });

    it('should add and remove address with drop strategy', async () => {
        await nftDrop.addAddress('192.168.88.88', '1m');
        await nftDrop.removeAddress('192.168.88.88');
    });

    it('should delete tables with drop strategy', async () => {
        await nftDrop.deleteTable();
    });
});

describe('NftManager tcp-reset strategy', { skip: !canCreateContext }, () => {
    let nftRst;

    after(async () => {
        try { if (nftRst) await nftRst.deleteTable(); } catch { /* ignore */ }
    });

    it('should create tables with tcp-reset strategy', async () => {
        nftRst = new NftManager({ strategy: 'tcp-reset' });
        await nftRst.createTable();
    });

    it('should add and remove address with tcp-reset strategy', async () => {
        await nftRst.addAddress('192.168.77.77', '1m');
        await nftRst.removeAddress('192.168.77.77');
    });

    it('should delete tables with tcp-reset strategy', async () => {
        await nftRst.deleteTable();
    });
});
