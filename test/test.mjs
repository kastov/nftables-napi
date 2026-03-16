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
        ingressAddrSets: ['blacklist', 'droplist'],
        egressAddrSets: ['blocked_ips'],
        egressPortSets: ['blocked_ports']
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
        assert.throws(() => new NftManager({ ingressAddrSets: ['bl'] }), { name: 'TypeError' });
    });

    it('should throw with non-string tableName', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 123, ingressAddrSets: ['bl'] }), { name: 'TypeError' });
    });

    it('should throw without ingressAddrSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't' }), { name: 'TypeError' });
    });

    it('should throw with non-array ingressAddrSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: 'bl' }), { name: 'TypeError' });
    });

    it('should throw with empty ingressAddrSets array', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: [] }));
    });

    it('should throw with non-string element in ingressAddrSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: [123] }), { name: 'TypeError' });
    });

    it('should throw with empty string in ingressAddrSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: [''] }));
    });

    it('should throw with duplicate set names in ingressAddrSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: ['bl', 'bl'] }));
    });

    // egressAddrSets validation
    it('should throw with non-array egressAddrSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: ['bl'], egressAddrSets: 'x' }), { name: 'TypeError' });
    });

    it('should throw with non-string in egressAddrSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: ['bl'], egressAddrSets: [123] }), { name: 'TypeError' });
    });

    it('should throw with empty string in egressAddrSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: ['bl'], egressAddrSets: [''] }));
    });

    // egressPortSets validation
    it('should throw with non-array egressPortSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: ['bl'], egressPortSets: 42 }), { name: 'TypeError' });
    });

    it('should throw with non-string in egressPortSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: ['bl'], egressPortSets: [true] }), { name: 'TypeError' });
    });

    // Cross-array duplicate check
    it('should throw with duplicate name across ingressAddrSets and egressAddrSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: ['bl'], egressAddrSets: ['bl'] }));
    });

    it('should throw with duplicate name across ingressAddrSets and egressPortSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({ tableName: 't', ingressAddrSets: ['bl'], egressPortSets: ['bl'] }));
    });

    it('should throw with duplicate name across egressAddrSets and egressPortSets', { skip: !canCreateContext }, () => {
        assert.throws(() => new NftManager({
            tableName: 't', ingressAddrSets: ['bl'], egressAddrSets: ['x'], egressPortSets: ['x']
        }));
    });

    // Valid constructions
    it('should create with single set (backward compat)', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ tableName: 'test', ingressAddrSets: ['ban'] });
        assert.ok(mgr);
    });

    it('should create with ingressAddrSets + egressAddrSets', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ tableName: 'test', ingressAddrSets: ['bl'], egressAddrSets: ['out'] });
        assert.ok(mgr);
    });

    it('should create with ingressAddrSets + egressPortSets', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ tableName: 'test', ingressAddrSets: ['bl'], egressPortSets: ['ports'] });
        assert.ok(mgr);
    });

    it('should create with all three', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({
            tableName: 'test', ingressAddrSets: ['a', 'b'], egressAddrSets: ['c'], egressPortSets: ['d']
        });
        assert.ok(mgr);
    });

    it('should accept empty egressAddrSets and egressPortSets', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ tableName: 'test', ingressAddrSets: ['bl'], egressAddrSets: [], egressPortSets: [] });
        assert.ok(mgr);
    });

    it('should accept undefined egressAddrSets and egressPortSets', { skip: !canCreateContext }, () => {
        const mgr = new NftManager({ tableName: 'test', ingressAddrSets: ['bl'] });
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

    it('should throw on addAddress with port set name', () => {
        assert.throws(() => nft.addAddress({ ip: '1.2.3.4', set: 'blocked_ports' }));
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

    it('should throw on addAddress with CIDR notation', () => {
        assert.throws(() => nft.addAddress({ ip: '192.168.1.0/24', set: 'blacklist' }));
    });

    // addAddress works with egressAddrSets
    it('should accept addAddress with egressAddrSet name', () => {
        // Should not throw synchronously (would fail asynchronously without table)
        const p = nft.addAddress({ ip: '1.2.3.4', set: 'blocked_ips', timeout: 60 });
        p.catch(() => {}); // suppress async rejection (no table created)
        assert.ok(p instanceof Promise);
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

    // removeAddresses validation
    it('should throw on removeAddresses without object', () => {
        assert.throws(() => nft.removeAddresses(['1.2.3.4']), { name: 'TypeError' });
    });

    it('should throw on removeAddresses with invalid set', () => {
        assert.throws(() => nft.removeAddresses({ ips: ['1.2.3.4'], set: 'invalid' }));
    });

    // ── Port method validation ──────────────────────────────────────────────

    // addPort
    it('should throw on addPort without object', () => {
        assert.throws(() => nft.addPort(443), { name: 'TypeError' });
    });

    it('should throw on addPort without port', () => {
        assert.throws(() => nft.addPort({ set: 'blocked_ports' }), { name: 'TypeError' });
    });

    it('should throw on addPort with string port', () => {
        assert.throws(() => nft.addPort({ port: '443', set: 'blocked_ports' }), { name: 'TypeError' });
    });

    it('should throw on addPort without set', () => {
        assert.throws(() => nft.addPort({ port: 443 }), { name: 'TypeError' });
    });

    it('should throw on addPort with IP set name', () => {
        assert.throws(() => nft.addPort({ port: 443, set: 'blacklist' }));
    });

    it('should throw on addPort with invalid port (-1)', () => {
        assert.throws(() => nft.addPort({ port: -1, set: 'blocked_ports' }));
    });

    it('should throw on addPort with invalid port (65536)', () => {
        assert.throws(() => nft.addPort({ port: 65536, set: 'blocked_ports' }));
    });

    it('should throw on addPort with fractional port', () => {
        assert.throws(() => nft.addPort({ port: 80.5, set: 'blocked_ports' }));
    });

    it('should throw on addPort with NaN port', () => {
        assert.throws(() => nft.addPort({ port: NaN, set: 'blocked_ports' }));
    });

    it('should throw on addPort with Infinity port', () => {
        assert.throws(() => nft.addPort({ port: Infinity, set: 'blocked_ports' }));
    });

    it('should throw on addPort with non-number timeout', () => {
        assert.throws(() => nft.addPort({ port: 443, set: 'blocked_ports', timeout: 'bad' }), { name: 'TypeError' });
    });

    // removePort
    it('should throw on removePort without object', () => {
        assert.throws(() => nft.removePort(443), { name: 'TypeError' });
    });

    it('should throw on removePort with invalid set', () => {
        assert.throws(() => nft.removePort({ port: 443, set: 'invalid' }));
    });

    // addPorts
    it('should throw on addPorts without object', () => {
        assert.throws(() => nft.addPorts([443]), { name: 'TypeError' });
    });

    it('should throw on addPorts without ports array', () => {
        assert.throws(() => nft.addPorts({ ports: 'not-array', set: 'blocked_ports' }), { name: 'TypeError' });
    });

    it('should throw on addPorts with invalid port in array', () => {
        assert.throws(() => nft.addPorts({ ports: [80, -1], set: 'blocked_ports' }));
    });

    it('should throw on addPorts with non-number in array', () => {
        assert.throws(() => nft.addPorts({ ports: [80, 'bad'], set: 'blocked_ports' }), { name: 'TypeError' });
    });

    // removePorts
    it('should throw on removePorts without object', () => {
        assert.throws(() => nft.removePorts([443]), { name: 'TypeError' });
    });

    it('should throw on removePorts with invalid set', () => {
        assert.throws(() => nft.removePorts({ ports: [443], set: 'invalid' }));
    });

    // Port 0 should be valid
    it('should accept port 0', () => {
        const p = nft.addPort({ port: 0, set: 'blocked_ports' });
        p.catch(() => {});
        assert.ok(p instanceof Promise);
    });

    it('should accept port 65535', () => {
        const p = nft.addPort({ port: 65535, set: 'blocked_ports' });
        p.catch(() => {});
        assert.ok(p instanceof Promise);
    });

    // protocol validation
    it('should throw on addPort with invalid protocol', () => {
        assert.throws(() => nft.addPort({ port: 443, set: 'blocked_ports', protocol: 'icmp' }));
    });

    it('should throw on addPort with non-string protocol', () => {
        assert.throws(() => nft.addPort({ port: 443, set: 'blocked_ports', protocol: 6 }), { name: 'TypeError' });
    });

    it('should accept addPort with tcp protocol', () => {
        const p = nft.addPort({ port: 443, set: 'blocked_ports', protocol: 'tcp' });
        p.catch(() => {});
        assert.ok(p instanceof Promise);
    });

    it('should accept addPort with udp protocol', () => {
        const p = nft.addPort({ port: 53, set: 'blocked_ports', protocol: 'udp' });
        p.catch(() => {});
        assert.ok(p instanceof Promise);
    });
});

// ─── Integration: input sets (blacklist) ────────────────────────────────────

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
            set: 'blacklist', timeout: 300
        });
    });

    it('should bulk remove', async () => {
        await nft.removeAddresses({
            ips: ['10.0.0.10', '10.0.0.11', '2001:db8::10'],
            set: 'blacklist'
        });
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

// ─── Integration: output IP sets ────────────────────────────────────────────

describe('NftManager integration (output IP)', { skip: !canCreateContext }, () => {
    after(async () => {
        try { await nft.deleteTable(); } catch { /* ignore */ }
    });

    it('should create tables with output sets', async () => {
        await nft.createTable();
    });

    it('should add IPv4 to output set', async () => {
        await nft.addAddress({ ip: '10.0.0.1', set: 'blocked_ips', timeout: 60 });
    });

    it('should add IPv6 to output set', async () => {
        await nft.addAddress({ ip: '2001:db8::1', set: 'blocked_ips' });
    });

    it('should remove from output set', async () => {
        await nft.removeAddress({ ip: '10.0.0.1', set: 'blocked_ips' });
        await nft.removeAddress({ ip: '2001:db8::1', set: 'blocked_ips' });
    });

    it('should bulk add to output set', async () => {
        await nft.addAddresses({ ips: ['10.1.1.1', '10.1.1.2'], set: 'blocked_ips', timeout: 120 });
    });

    it('should bulk remove from output set', async () => {
        await nft.removeAddresses({ ips: ['10.1.1.1', '10.1.1.2'], set: 'blocked_ips' });
    });

    it('should delete tables', async () => {
        await nft.deleteTable();
    });
});

// ─── Integration: output port sets ──────────────────────────────────────────

describe('NftManager integration (output ports)', { skip: !canCreateContext }, () => {
    after(async () => {
        try { await nft.deleteTable(); } catch { /* ignore */ }
    });

    it('should create tables', async () => {
        await nft.createTable();
    });

    it('should add tcp port with timeout', async () => {
        await nft.addPort({ port: 443, set: 'blocked_ports', protocol: 'tcp', timeout: 60 });
    });

    it('should add udp port', async () => {
        await nft.addPort({ port: 53, set: 'blocked_ports', protocol: 'udp' });
    });

    it('should add port for both protocols (default)', async () => {
        await nft.addPort({ port: 80, set: 'blocked_ports', timeout: 120 });
    });

    it('should add port 0 tcp', async () => {
        await nft.addPort({ port: 0, set: 'blocked_ports', protocol: 'tcp', timeout: 30 });
    });

    it('should remove tcp port', async () => {
        await nft.removePort({ port: 443, set: 'blocked_ports', protocol: 'tcp' });
    });

    it('should remove udp port', async () => {
        await nft.removePort({ port: 53, set: 'blocked_ports', protocol: 'udp' });
    });

    it('should remove both protocols (default)', async () => {
        await nft.removePort({ port: 80, set: 'blocked_ports' });
    });

    it('should remove port idempotently', async () => {
        await nft.removePort({ port: 443, set: 'blocked_ports', protocol: 'tcp' });
    });

    it('should bulk add ports with protocol', async () => {
        await nft.addPorts({ ports: [8080, 8443], set: 'blocked_ports', protocol: 'tcp', timeout: 180 });
    });

    it('should bulk add ports both protocols', async () => {
        await nft.addPorts({ ports: [3000], set: 'blocked_ports' });
    });

    it('should bulk remove ports', async () => {
        await nft.removePorts({ ports: [8080, 8443], set: 'blocked_ports', protocol: 'tcp' });
        await nft.removePorts({ ports: [3000, 0], set: 'blocked_ports' });
    });

    it('should handle empty port arrays', async () => {
        await nft.addPorts({ ports: [], set: 'blocked_ports', timeout: 60 });
        await nft.removePorts({ ports: [], set: 'blocked_ports' });
    });

    it('should delete tables', async () => {
        await nft.deleteTable();
    });
});

// ─── Integration: backward compat (ingressAddrSets only) ────────────────────

describe('NftManager integration (backward compat)', { skip: !canCreateContext }, () => {
    let simple;

    after(async () => {
        try { await simple.deleteTable(); } catch { /* ignore */ }
    });

    it('should create with ingressAddrSets only (no egressAddrSets/egressPortSets)', async () => {
        simple = new NftManager({ tableName: 'backcompat', ingressAddrSets: ['ban'] });
        await simple.createTable();
    });

    it('should add and remove from set', async () => {
        await simple.addAddress({ ip: '10.0.0.1', set: 'ban', timeout: 60 });
        await simple.removeAddress({ ip: '10.0.0.1', set: 'ban' });
    });

    it('should delete tables', async () => {
        await simple.deleteTable();
    });
});

// ─── Integration: full config ───────────────────────────────────────────────

describe('NftManager integration (full config)', { skip: !canCreateContext }, () => {
    let full;

    after(async () => {
        try { await full.deleteTable(); } catch { /* ignore */ }
    });

    it('should create with all set types', async () => {
        full = new NftManager({
            tableName: 'fulltest',
            ingressAddrSets: ['banlist', 'droplist'],
            egressAddrSets: ['out_blocked'],
            egressPortSets: ['out_ports']
        });
        await full.createTable();
    });

    it('should add to input set', async () => {
        await full.addAddress({ ip: '10.0.0.1', set: 'banlist', timeout: 60 });
    });

    it('should add to output IP set', async () => {
        await full.addAddress({ ip: '10.0.0.2', set: 'out_blocked' });
    });

    it('should add tcp port to output port set', async () => {
        await full.addPort({ port: 25, set: 'out_ports', protocol: 'tcp', timeout: 300 });
    });

    it('should reject IP method on port set', () => {
        assert.throws(() => full.addAddress({ ip: '10.0.0.3', set: 'out_ports' }));
    });

    it('should reject port method on IP set', () => {
        assert.throws(() => full.addPort({ port: 80, set: 'banlist' }));
    });

    it('should clean up', async () => {
        await full.removeAddress({ ip: '10.0.0.1', set: 'banlist' });
        await full.removeAddress({ ip: '10.0.0.2', set: 'out_blocked' });
        await full.removePort({ port: 25, set: 'out_ports', protocol: 'tcp' });
        await full.deleteTable();
    });
});
