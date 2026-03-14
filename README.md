# nftables-napi

Native Node.js binding for nftables via libnftnl + libmnl. Manages IPv4/IPv6 firewall tables with dynamic IP sets, port blocking, named counters, and timeout support through direct netlink communication — no shell commands, no `nft` CLI.

Requires Linux kernel ≥ 5.7 with `CAP_NET_ADMIN` or root.

## Install

```bash
npm install nftables-napi
```

Prebuilt binaries are included for `linux-x64` and `linux-arm64`. If a prebuild is not available for your platform, the package will compile from source (requires `libnftnl-dev`, `libmnl-dev`, `pkg-config`, and a C++20 compiler).

### Runtime dependencies

The module dynamically links against `libnftnl` and `libmnl`. These must be present in the runtime environment. The `nft` CLI is **not** required — the module talks to the kernel directly via netlink.

**Alpine:**

```dockerfile
RUN apk add --no-cache libnftnl libmnl
```

**Debian/Ubuntu:**

```dockerfile
RUN apt-get update && apt-get install -y libnftnl13 libmnl0 && rm -rf /var/lib/apt/lists/*
```

## Usage

```js
const { NftManager } = require("nftables-napi");

const nft = new NftManager({
  tableName: "myfw",
  sets: ["blacklist"],
  outSets: ["blocklist"],
  outPortSets: ["blocked_ports"],
});

await nft.createTable();

// ── IP blocking (input/forward) ──

await nft.addAddress({ ip: "1.2.3.4", set: "blacklist", timeout: 1800 });
await nft.addAddress({ ip: "2001:db8::1", set: "blacklist", timeout: 3600 });
await nft.addAddresses({ ips: ["10.0.0.1", "10.0.0.2"], set: "blacklist", timeout: 7200 });

await nft.removeAddress({ ip: "1.2.3.4", set: "blacklist" });
await nft.removeAddresses({ ips: ["10.0.0.1", "10.0.0.2"], set: "blacklist" });

// ── IP blocking (output) ──

await nft.addAddress({ ip: "93.184.216.34", set: "blocklist" });
await nft.removeAddress({ ip: "93.184.216.34", set: "blocklist" });

// ── Port blocking (output, tcp/udp) ──

// Block port 80 for both TCP and UDP
await nft.addPort({ port: 80, set: "blocked_ports", timeout: 3600 });

// Block port 443 for TCP only
await nft.addPort({ port: 443, set: "blocked_ports", protocol: "tcp" });

// Bulk port operations
await nft.addPorts({ ports: [8080, 8443], set: "blocked_ports", protocol: "tcp" });
await nft.removePorts({ ports: [8080, 8443], set: "blocked_ports", protocol: "tcp" });

await nft.removePort({ port: 80, set: "blocked_ports" });

// ── Cleanup ──

await nft.deleteTable();
```

## API

### `new NftManager(options)`

| Option | Type | Required | Description |
| --- | --- | --- | --- |
| `tableName` | `string` | Yes | Base table name. IPv6 table auto-appends `'6'`. |
| `sets` | `string[]` | Yes | Input/forward IP set names (≥1). Block by **source** address on input and forward chains. Rules: log + named counter + drop. IPv6 sets auto-append `'6'`. |
| `outSets` | `string[]` | No | Output IP set names. Block by **destination** address on output chain. Rules: named counter + drop (no log). IPv6 sets auto-append `'6'`. |
| `outPortSets` | `string[]` | No | Output port set names. Block by **destination port** (TCP/UDP) on output chain using concatenated `inet_proto . inet_service` sets. Ports are added to both IPv4 and IPv6 tables. IPv6 sets auto-append `'6'`. |

### Methods

All methods return `Promise<void>` and throw on error.

#### Table management

| Method | Description |
| --- | --- |
| `createTable()` | Create IPv4/IPv6 tables with all configured sets, chains, named counters, and filter rules. Idempotent — deletes existing tables first. |
| `deleteTable()` | Delete both tables. Idempotent — no error if tables don't exist. |

#### IP address operations

Work with both `sets` (input/forward) and `outSets` (output).

| Method | Description |
| --- | --- |
| `addAddress({ ip, set, timeout? })` | Add IP to set. Auto-detects IPv4/IPv6. `timeout` in seconds, omit for permanent. |
| `removeAddress({ ip, set })` | Remove IP from set. Idempotent. |
| `addAddresses({ ips, set, timeout? })` | Bulk add. Chunked internally for efficient netlink communication. Empty array is a no-op. |
| `removeAddresses({ ips, set })` | Bulk remove. Idempotent. Empty array is a no-op. |

#### Port operations

Work with `outPortSets` only. Ports are added to both IPv4 and IPv6 tables.

| Method | Description |
| --- | --- |
| `addPort({ port, set, protocol?, timeout? })` | Add port to set. `protocol`: `'tcp'`, `'udp'`, or omit for both. `timeout` in seconds. |
| `removePort({ port, set, protocol? })` | Remove port from set. Idempotent. |
| `addPorts({ ports, set, protocol?, timeout? })` | Bulk add ports. Empty array is a no-op. |
| `removePorts({ ports, set, protocol? })` | Bulk remove ports. Idempotent. Empty array is a no-op. |

### What `createTable()` builds

For a config with `sets: ["bl"]`, `outSets: ["out"]`, `outPortSets: ["ports"]`:

```
table ip myfw {
    counter "processed" { packets 0 bytes 0 }
    counter "bl"        { packets 0 bytes 0 }
    counter "out"       { packets 0 bytes 0 }
    counter "ports"     { packets 0 bytes 0 }

    set bl {
        type ipv4_addr
        flags timeout
        counter
    }

    set out {
        type ipv4_addr
        flags timeout
        counter
    }

    set ports {
        type inet_proto . inet_service
        flags timeout
        counter
    }

    chain input {
        type filter hook input priority -10; policy accept;
        counter name "processed"
        ip saddr @bl log prefix "bl: " counter name "bl" drop
    }

    chain forward {
        type filter hook forward priority -10; policy accept;
        counter name "processed"
        ip saddr @bl log prefix "bl: " counter name "bl" drop
    }

    chain output {
        type filter hook output priority -10; policy accept;
        ip daddr @out counter name "out" drop
        meta l4proto . th dport @ports counter name "ports" drop
    }
}
```

IPv6 table (`myfw6`) mirrors the same structure with `ipv6_addr` sets and corresponding offsets.

## Kernel compatibility

Minimum: **Linux 5.7**

| Feature | Kernel | Used for |
| --- | --- | --- |
| nftables core | 3.13 | tables, chains, sets, rules |
| Set timeouts | 4.1 | element expiration |
| Named counters | 4.10 | traffic accounting |
| Concatenated sets | 5.6 | port blocking (`inet_proto . inet_service`) |
| Per-element set expressions | 5.7 | per-element counters |

| Distro | Kernel | Compatible |
| --- | --- | --- |
| Ubuntu 22.04+ | 5.15+ | Yes |
| Ubuntu 20.04 (HWE) | 5.15 | Yes |
| Ubuntu 20.04 (GA) | 5.4 | No |
| Debian 11+ | 5.10+ | Yes |
| Debian 10 | 4.19 | No |
| RHEL / Rocky 9 | 5.14 | Yes |
| RHEL / Rocky 8 | 4.18 | No |
| Alpine 3.16+ | 5.15+ | Yes |

## Building from source

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install pkg-config libnftnl-dev libmnl-dev build-essential

# Dependencies (Alpine)
apk add pkgconfig libnftnl-dev libmnl-dev build-base python3

# Build
npm run build

# Run tests (requires root / CAP_NET_ADMIN)
npm test

# Prebuild for current platform
npx prebuildify --napi --strip

# Prebuild for linux/amd64 + linux/arm64 via Docker
npm run prebuild:all
```

## License

AGPL-3.0-only
