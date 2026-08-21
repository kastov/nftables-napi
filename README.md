# nftables-napi

Native Node.js binding for nftables via libnftnl + libmnl. Manages IPv4/IPv6 firewall tables with dynamic IP sets, port blocking, named counters, and timeout support through direct netlink communication — no shell commands, no `nft` CLI.

Requires Node.js ≥ 24 and a Linux kernel ≥ 5.7 with `CAP_NET_ADMIN` or root.

## Install

```bash
npm install nftables-napi
```

Prebuilt binaries ship for `linux-x64` and `linux-arm64`, in glibc and musl flavors. Nothing
is compiled at install time — the package has **no runtime dependencies** and no build toolchain
is ever invoked on your machine.

| Flavor  | Runtime          | Covers                                        |
| ------- | ---------------- | --------------------------------------------- |
| `glibc` | glibc ≥ 2.28    | Debian 10+, Ubuntu 18.10+, RHEL 8+, Amazon Linux 2023 |
| `musl`  | musl             | Alpine                                        |

The loader picks the flavor from the host libc and falls back to probing, so the right binary is
used automatically. The binaries declare Node-API v10, which is why Node 24 is the floor; glibc
2.28 is Node's own floor, so any host that can run Node 24 can run this.

### Runtime dependencies

None. `libnftnl` and `libmnl` are linked **statically** into the binary, so there is nothing to
`apk add` or `apt-get install`. The `nft` CLI is not required either — the module talks to the
kernel directly via netlink.

```dockerfile
FROM node:24-alpine
RUN npm install nftables-napi   # that's it
```

## Usage

```js
const { NftManager } = require("nftables-napi");

const nft = new NftManager({
  tableName: "myfw",
  ingressAddrSets: ["blacklist"],
  egressAddrSets: ["blocklist"],
  egressPortSets: ["blocked_ports"],
});

await nft.createTable();

// Same, but without any kernel logging of ingress drops:
// new NftManager({ tableName: "myfw", ingressAddrSets: ["blacklist"], logging: false })

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
| `ingressAddrSets` | `string[]` | Yes | Input/forward IP set names (≥1). Block by **source** address on input and forward chains. Rules: log + named counter + drop (log omitted when `logging: false`). IPv6 sets auto-append `'6'`. |
| `egressAddrSets` | `string[]` | No | Output IP set names. Block by **destination** address on output chain. Rules: named counter + drop (no log). IPv6 sets auto-append `'6'`. |
| `egressPortSets` | `string[]` | No | Output port set names. Block by **destination port** (TCP/UDP) on output chain using concatenated `inet_proto . inet_service` sets. Ports are added to both IPv4 and IPv6 tables. IPv6 sets auto-append `'6'`. |
| `logging` | `boolean` | No | Log ingress drops. Default `true`. Set to `false` to build the tables without any log expression — see [Disabling logging](#disabling-logging). |
| `acceptReplyTraffic` | `boolean` | No | Accept reply traffic before the ingress sets are consulted. Default `true`. See [Reply traffic and conntrack](#reply-traffic-and-conntrack). |

### Methods

All methods return `Promise<void>` and throw on error.

#### Table management

| Method | Description |
| --- | --- |
| `createTable()` | Create IPv4/IPv6 tables with all configured sets, chains, named counters, and filter rules. Idempotent — deletes existing tables first. |
| `deleteTable()` | Delete both tables. Idempotent — no error if tables don't exist. |

#### IP address operations

Work with both `ingressAddrSets` (input/forward) and `egressAddrSets` (output).

| Method | Description |
| --- | --- |
| `addAddress({ ip, set, timeout? })` | Add IP to set. Auto-detects IPv4/IPv6. `timeout` in seconds, omit for permanent. |
| `removeAddress({ ip, set })` | Remove IP from set. Idempotent. |
| `addAddresses({ ips, set, timeout? })` | Bulk add. Chunked internally for efficient netlink communication. Empty array is a no-op. |
| `removeAddresses({ ips, set })` | Bulk remove. Idempotent. Empty array is a no-op. |

#### Port operations

Work with `egressPortSets` only. Ports are added to both IPv4 and IPv6 tables.

| Method | Description |
| --- | --- |
| `addPort({ port, set, protocol?, timeout? })` | Add port to set. `protocol`: `'tcp'`, `'udp'`, or omit for both. `timeout` in seconds. |
| `removePort({ port, set, protocol? })` | Remove port from set. Idempotent. |
| `addPorts({ ports, set, protocol?, timeout? })` | Bulk add ports. Empty array is a no-op. |
| `removePorts({ ports, set, protocol? })` | Bulk remove ports. Idempotent. Empty array is a no-op. |

### What `createTable()` builds

For a config with `ingressAddrSets: ["bl"]`, `egressAddrSets: ["out"]`, `egressPortSets: ["ports"]`:

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
        ct direction reply accept
        ip saddr @bl log prefix "bl: " counter name "bl" drop
    }

    chain forward {
        type filter hook forward priority -10; policy accept;
        counter name "processed"
        ct direction reply accept
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

### Reply traffic and conntrack

The ingress rules match `ip saddr` — the packet's source, which in the input chain is the
remote peer of **every** inbound packet, including the SYN-ACK answering a connection this host
opened itself. A stateless `ip saddr @set drop` therefore cannot tell "someone is connecting to
me" from "the site I just requested is answering".

If an ingress set contains a network the host itself talks to, outbound connections to it break:
the SYN leaves through the output chain, and the reply is dropped on the way back. The symptom is
a connection that hangs and times out, while the set's counter fills up — with your own reply
packets, not with blocked connection attempts.

`createTable()` therefore emits, at the top of the input and forward chains:

```
counter name "processed"
ct direction reply accept
ip saddr @bl log prefix "bl: " counter name "bl" drop
```

The test is conntrack **direction**, not state. Direction is what separates the two cases: for a
connection this host opened, inbound packets travel in the reply direction; for a connection
opened to this host, they travel in the original direction. State cannot express the difference —
`NF_CT_STATE_BIT()` reduces `ctinfo` modulo `IP_CT_IS_REPLY`, so `IP_CT_ESTABLISHED` and
`IP_CT_ESTABLISHED_REPLY` land on the same bit and the direction is gone before a rule can look
at it.

Consequently the sets keep full authority over connections opened to this host: adding an address
drops its packets immediately, established sessions included, exactly as it did before this rule
existed. Only replies to locally-originated connections bypass the sets. The `processed` counter
still sees every packet because it precedes the accept, and the output chain is untouched.

Two things worth knowing:

- **conntrack becomes a dependency.** The rule makes nftables pull in connection tracking for that
  family, and `createTable()` fails if the kernel cannot provide it — and because the batch is
  atomic, nothing at all is created in that case. On a host already running Docker this changes
  nothing; conntrack is loaded for NAT anyway. On a bare host with a high connection rate,
  `nf_conntrack_max` becomes a ceiling worth checking.
- **Connections this host originated are not severed** when the peer's address is added to a set —
  their replies are accepted before the set is consulted. Drop the conntrack entries
  (`conntrack -D -d <ip>`) alongside `addAddress()` if that matters.

Pass `acceptReplyTraffic: false` to build the chains without it and get the previous, purely
stateless behaviour:

```js
const nft = new NftManager({
  tableName: "myfw",
  ingressAddrSets: ["bl"],
  acceptReplyTraffic: false,
});
```

### Disabling logging

Ingress drops are logged by default with the prefix `"<setName>: "`. On a busy host this can flood
`dmesg`/journald and cost measurable CPU. Pass `logging: false` to build the tables without it:

```js
const nft = new NftManager({
  tableName: "myfw",
  ingressAddrSets: ["bl"],
  logging: false,
});

await nft.createTable();
```

The `log` expression is then not emitted into the rules at all — this is not "log at a silent level",
the kernel does no logging work whatsoever:

```
    chain input {
        type filter hook input priority -10; policy accept;
        counter name "processed"
        ip saddr @bl counter name "bl" drop
    }
```

Per-set and named counters are unaffected, so blocked-traffic accounting keeps working. The flag only
affects `ingressAddrSets`; `egressAddrSets` and `egressPortSets` never logged in the first place.

The flag is read when the rules are built, i.e. by `createTable()` — construct the manager with the
desired value and call `createTable()` for it to take effect.

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

The build cross-compiles every target from a single machine using [Zig](https://ziglang.org/) as
the C/C++ toolchain — no node-gyp, no Docker, no QEMU. It runs on macOS or Linux, x64 or arm64.

```bash
npm install

# Build all four binaries into prebuilds/. Downloads a pinned Zig on first run
# and cross-builds static libnftnl + libmnl into .deps/ (both cached).
npm run build

# Or just one target
node scripts/build.mjs linux-arm64-musl

# Run tests (needs Linux + CAP_NET_ADMIN)
npm test
```

To test a locally built binary against an installed copy, point at it directly:

```bash
NFTABLES_NAPI_BINDING=./prebuilds/linux-x64/nftables-napi.musl.node node -e "require('nftables-napi')"
```

The dependency build only prints progress; if a `configure` or `make` step fails its output is
replayed automatically. Set `VERBOSE=1` to see everything as it happens, or `ZIG=/path/to/zig` to
use an existing toolchain instead of the pinned download. The target
matrix lives in [`scripts/targets.mjs`](scripts/targets.mjs); adding an architecture is a matter
of adding an entry, since Zig can already target it.

## License

AGPL-3.0-only
