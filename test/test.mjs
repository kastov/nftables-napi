import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { NftManager } = require('../lib/index.js');

let canCreateContext = false;
let nft;
try {
    nft = new NftManager({
        tableName: 'remnawave',
        sets: ['blacklist', 'droplist']
    });
    canCreateContext = true;
} catch {
    // No root/CAP_NET_ADMIN
}

// ─── Constructor validation ─────────────────────────────────────────────────

describe('NftManager constructor validation', () => {
    it('should export NftManager as a function/class', () => {
        assert.equal(typeof NftManager, 'function');
    });

    it('should throw without options', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager(), { name: 'TypeError' });
    });

    it('should throw with empty object', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({}), { name: 'TypeError' });
    });

    it('should throw without tableName', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ sets: ['bl'] }), { name: 'TypeError' });
    });

    it('should throw with non-string tableName', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 123, sets: ['bl'] }), { name: 'TypeError' });
    });

    it('should throw without sets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't' }), { name: 'TypeError' });
    });

    it('should throw with non-array sets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', sets: 'bl' }), { name: 'TypeError' });
    });

    it('should throw with empty sets array', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', sets: [] }));
    });

    it('should throw with non-string element in sets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', sets: [123] }), { name: 'TypeError' });
    });

    it('should throw with empty string in sets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', sets: [''] }));
    });

    it('should throw with duplicate set names', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', sets: ['bl', 'bl'] }));
    });

    it('should create with single set', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ tableName: 'test', sets: ['ban'] });
        assert.ok(mgr);
    });

    it('should create with two sets', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ tableName: 'test', sets: ['bl', 'dl'] });
        assert.ok(mgr);
    });

    it('should create with three sets', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ tableName: 'test', sets: ['a', 'b', 'c'] });
        assert.ok(mgr);
    });
});

// ─── Method validation ──────────────────────────────────────────────────────

describe('NftManager method validation', { skip: !canCreateContext }, () => {
    // addAddress validation
    it('should throw on addAddress without object', () => {
        assert.throws(() => nft.addAddress('1.2.3.4'), { name: 'TypeError' });
    });

    it('should throw on addAddress without ip', () => {
        assert.throws(() => nft.addAddress({ set: 'blacklist' }), { name: 'TypeError' });
    });

    it('should throw on addAddress without set', () => {
        assert.throws(() => nft.addAddress({ ip: '1.2.3.4' }), { name: 'TypeError' });
    });

    it('should throw on addAddress with invalid set name', () => {
        assert.throws(() => nft.addAddress({ ip: '1.2.3.4', set: 'nonexistent' }));
    });

    it('should throw on addAddress with invalid IP', () => {
        assert.throws(() => nft.addAddress({ ip: 'not-an-ip', set: 'blacklist' }));
    });

    it('should throw on addAddress with non-number timeout', () => {
        assert.throws(() => nft.addAddress({ ip: '1.2.3.4', set: 'blacklist', timeout: 'bad' }), { name: 'TypeError' });
    });

    it('should throw on addAddress with zero timeout', () => {
        assert.throws(() => nft.addAddress({ ip: '1.2.3.4', set: 'blacklist', timeout: 0 }));
    });

    it('should throw on addAddress with negative timeout', () => {
        assert.throws(() => nft.addAddress({ ip: '1.2.3.4', set: 'blacklist', timeout: -1 }));
    });

    it('should throw on addAddress with NaN timeout', () => {
        assert.throws(() => nft.addAddress({ ip: '1.2.3.4', set: 'blacklist', timeout: NaN }));
    });

    it('should throw on addAddress with Infinity timeout', () => {
        assert.throws(() => nft.addAddress({ ip: '1.2.3.4', set: 'blacklist', timeout: Infinity }));
    });

    it('should throw on addAddress with -Infinity timeout', () => {
        assert.throws(() => nft.addAddress({ ip: '1.2.3.4', set: 'blacklist', timeout: -Infinity }));
    });

    it('should throw on addAddress with CIDR notation', () => {
        assert.throws(() => nft.addAddress({ ip: '192.168.1.0/24', set: 'blacklist' }));
    });

    it('should throw on addAddress with port notation', () => {
        assert.throws(() => nft.addAddress({ ip: '192.168.1.1:8080', set: 'blacklist' }));
    });

    it('should throw on addAddress with empty IP', () => {
        assert.throws(() => nft.addAddress({ ip: '', set: 'blacklist' }));
    });

    it('should throw on addAddress with whitespace IP', () => {
        assert.throws(() => nft.addAddress({ ip: '  1.2.3.4', set: 'blacklist' }));
    });

    // removeAddress validation
    it('should throw on removeAddress without object', () => {
        assert.throws(() => nft.removeAddress('1.2.3.4'), { name: 'TypeError' });
    });

    it('should throw on removeAddress without ip', () => {
        assert.throws(() => nft.removeAddress({ set: 'blacklist' }), { name: 'TypeError' });
    });

    it('should throw on removeAddress with invalid set', () => {
        assert.throws(() => nft.removeAddress({ ip: '1.2.3.4', set: 'invalid' }));
    });

    it('should throw on removeAddress without set', () => {
        assert.throws(() => nft.removeAddress({ ip: '1.2.3.4' }), { name: 'TypeError' });
    });

    // addAddresses validation
    it('should throw on addAddresses without object', () => {
        assert.throws(() => nft.addAddresses(['1.2.3.4']), { name: 'TypeError' });
    });

    it('should throw on addAddresses without ips array', () => {
        assert.throws(() => nft.addAddresses({ ips: 'not-array', set: 'blacklist' }), { name: 'TypeError' });
    });

    it('should throw on addAddresses with invalid IP in array', () => {
        assert.throws(() => nft.addAddresses({ ips: ['1.2.3.4', 'invalid'], set: 'blacklist' }));
    });

    it('should throw on addAddresses with invalid set', () => {
        assert.throws(() => nft.addAddresses({ ips: ['1.2.3.4'], set: 'invalid' }));
    });

    it('should throw on addAddresses with non-number timeout', () => {
        assert.throws(() => nft.addAddresses({ ips: ['1.2.3.4'], set: 'blacklist', timeout: 'bad' }), { name: 'TypeError' });
    });

    it('should throw on addAddresses with zero timeout', () => {
        assert.throws(() => nft.addAddresses({ ips: ['1.2.3.4'], set: 'blacklist', timeout: 0 }));
    });

    it('should throw on addAddresses with negative timeout', () => {
        assert.throws(() => nft.addAddresses({ ips: ['1.2.3.4'], set: 'blacklist', timeout: -1 }));
    });

    // removeAddresses validation
    it('should throw on removeAddresses without object', () => {
        assert.throws(() => nft.removeAddresses(['1.2.3.4']), { name: 'TypeError' });
    });

    it('should throw on removeAddresses with invalid IP', () => {
        assert.throws(() => nft.removeAddresses({ ips: ['invalid'], set: 'blacklist' }));
    });

    it('should throw on removeAddresses without set', () => {
        assert.throws(() => nft.removeAddresses({ ips: ['1.2.3.4'] }), { name: 'TypeError' });
    });

    it('should throw on removeAddresses with invalid set', () => {
        assert.throws(() => nft.removeAddresses({ ips: ['1.2.3.4'], set: 'invalid' }));
    });
});

// ─── Integration: blacklist set ─────────────────────────────────────────────

describe('NftManager integration (blacklist)', { skip: !canCreateContext }, () => {
    after(async () => {
        try { await nft.deleteTable(); } catch { /* ignore */ }
    });

    it('should create tables', async () => {
        await nft.createTable();
    });

    it('should create tables idempotently', async () => {
        await nft.createTable();
    });

    it('should add IPv4 with timeout', async () => {
        await nft.addAddress({ ip: '192.168.99.99', set: 'blacklist', timeout: 60 });
    });

    it('should add IPv6 with timeout', async () => {
        await nft.addAddress({ ip: '2001:db8::dead:beef', set: 'blacklist', timeout: 120 });
    });

    it('should add IPv4 permanent (no timeout)', async () => {
        await nft.addAddress({ ip: '10.0.0.1', set: 'blacklist' });
    });

    it('should remove IPv4', async () => {
        await nft.removeAddress({ ip: '192.168.99.99', set: 'blacklist' });
    });

    it('should remove IPv6', async () => {
        await nft.removeAddress({ ip: '2001:db8::dead:beef', set: 'blacklist' });
    });

    it('should remove permanent address', async () => {
        await nft.removeAddress({ ip: '10.0.0.1', set: 'blacklist' });
    });

    it('should remove non-existent idempotently', async () => {
        await nft.removeAddress({ ip: '172.16.0.1', set: 'blacklist' });
    });

    it('should bulk add with timeout', async () => {
        await nft.addAddresses({
            ips: ['10.0.0.10', '10.0.0.11', '2001:db8::10'],
            set: 'blacklist',
            timeout: 300
        });
    });

    it('should bulk add permanent', async () => {
        await nft.addAddresses({
            ips: ['10.0.0.20', '10.0.0.21'],
            set: 'blacklist'
        });
    });

    it('should bulk remove', async () => {
        await nft.removeAddresses({
            ips: ['10.0.0.10', '10.0.0.11', '2001:db8::10', '10.0.0.20', '10.0.0.21'],
            set: 'blacklist'
        });
    });

    it('should bulk remove non-existent idempotently', async () => {
        await nft.removeAddresses({ ips: ['172.16.0.100'], set: 'blacklist' });
    });

    it('should handle empty arrays', async () => {
        await nft.addAddresses({ ips: [], set: 'blacklist', timeout: 60 });
        await nft.removeAddresses({ ips: [], set: 'blacklist' });
    });

    it('should delete tables', async () => {
        await nft.deleteTable();
    });

    it('should delete tables idempotently', async () => {
        await nft.deleteTable();
    });
});

// ─── Integration: droplist set ──────────────────────────────────────────────

describe('NftManager integration (droplist)', { skip: !canCreateContext }, () => {
    after(async () => {
        try { await nft.deleteTable(); } catch { /* ignore */ }
    });

    it('should create tables', async () => {
        await nft.createTable();
    });

    it('should add IPv4 to droplist with timeout', async () => {
        await nft.addAddress({ ip: '192.168.88.88', set: 'droplist', timeout: 60 });
    });

    it('should add IPv6 to droplist permanent', async () => {
        await nft.addAddress({ ip: '2001:db8::cafe:babe', set: 'droplist' });
    });

    it('should remove from droplist', async () => {
        await nft.removeAddress({ ip: '192.168.88.88', set: 'droplist' });
    });

    it('should remove non-existent from droplist idempotently', async () => {
        await nft.removeAddress({ ip: '172.16.0.1', set: 'droplist' });
    });

    it('should bulk add to droplist', async () => {
        await nft.addAddresses({ ips: ['10.1.1.1', '10.1.1.2'], set: 'droplist', timeout: 180 });
    });

    it('should bulk remove from droplist', async () => {
        await nft.removeAddresses({ ips: ['10.1.1.1', '10.1.1.2', '2001:db8::cafe:babe'], set: 'droplist' });
    });

    it('should bulk remove non-existent from droplist', async () => {
        await nft.removeAddresses({ ips: ['172.16.0.200'], set: 'droplist' });
    });

    it('should delete tables', async () => {
        await nft.deleteTable();
    });
});

// ─── Integration: custom config with actual names ───────────────────────────

describe('NftManager integration (custom config)', { skip: !canCreateContext }, () => {
    let custom;

    after(async () => {
        try { await custom.deleteTable(); } catch { /* ignore */ }
    });

    it('should create with custom names', async () => {
        custom = new NftManager({
            tableName: 'testfw',
            sets: ['testbl', 'testdrop']
        });
        await custom.createTable();
    });

    it('should add and remove from custom set', async () => {
        await custom.addAddress({ ip: '10.99.99.1', set: 'testbl', timeout: 60 });
        await custom.removeAddress({ ip: '10.99.99.1', set: 'testbl' });
    });

    it('should add permanent to second custom set', async () => {
        await custom.addAddress({ ip: '10.99.99.2', set: 'testdrop' });
        await custom.removeAddress({ ip: '10.99.99.2', set: 'testdrop' });
    });

    it('should delete custom tables', async () => {
        await custom.deleteTable();
    });
});

// ─── Integration: 3+ sets ───────────────────────────────────────────────────

describe('NftManager integration (three sets)', { skip: !canCreateContext }, () => {
    let multi;

    after(async () => {
        try { await multi.deleteTable(); } catch { /* ignore */ }
    });

    it('should create with three sets', async () => {
        multi = new NftManager({
            tableName: 'multitest',
            sets: ['banlist', 'droplist', 'ratelimit']
        });
        await multi.createTable();
    });

    it('should add to first set', async () => {
        await multi.addAddress({ ip: '10.0.0.1', set: 'banlist', timeout: 60 });
    });

    it('should add to second set', async () => {
        await multi.addAddress({ ip: '10.0.0.2', set: 'droplist' });
    });

    it('should add to third set', async () => {
        await multi.addAddress({ ip: '10.0.0.3', set: 'ratelimit', timeout: 30 });
    });

    it('should add IPv6 to third set', async () => {
        await multi.addAddress({ ip: '2001:db8::99', set: 'ratelimit', timeout: 30 });
    });

    it('should reject invalid set name', () => {
        assert.throws(() => multi.addAddress({ ip: '10.0.0.4', set: 'nonexistent' }));
    });

    it('should bulk add to third set', async () => {
        await multi.addAddresses({ ips: ['10.0.0.10', '10.0.0.11'], set: 'ratelimit', timeout: 120 });
    });

    it('should remove from all sets', async () => {
        await multi.removeAddress({ ip: '10.0.0.1', set: 'banlist' });
        await multi.removeAddress({ ip: '10.0.0.2', set: 'droplist' });
        await multi.removeAddress({ ip: '10.0.0.3', set: 'ratelimit' });
        await multi.removeAddress({ ip: '2001:db8::99', set: 'ratelimit' });
        await multi.removeAddresses({ ips: ['10.0.0.10', '10.0.0.11'], set: 'ratelimit' });
    });

    it('should delete tables', async () => {
        await multi.deleteTable();
    });
});

// ─── Integration: single set ────────────────────────────────────────────────

describe('NftManager integration (single set)', { skip: !canCreateContext }, () => {
    let single;

    after(async () => {
        try { await single.deleteTable(); } catch { /* ignore */ }
    });

    it('should create with single set', async () => {
        single = new NftManager({
            tableName: 'singletest',
            sets: ['ban']
        });
        await single.createTable();
    });

    it('should add and remove from single set', async () => {
        await single.addAddress({ ip: '10.0.0.1', set: 'ban', timeout: 60 });
        await single.removeAddress({ ip: '10.0.0.1', set: 'ban' });
    });

    it('should delete tables', async () => {
        await single.deleteTable();
    });
});
