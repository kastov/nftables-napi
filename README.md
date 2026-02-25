# nftables-napi

Native Node.js binding for nftables via libnftnl + libmnl. Manages IPv4/IPv6 blacklist tables with timeout support through direct netlink communication — no shell commands, no `nft` CLI.

Requires Linux with `CAP_NET_ADMIN` or root.

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
const { NftManager } = require('nftables-napi');

const nft = new NftManager({ strategy: 'reject' });

await nft.createTable();

await nft.addAddress('1.2.3.4', '30m');
await nft.addAddress('2001:db8::1', '1h');

await nft.addAddresses(['10.0.0.1', '10.0.0.2'], '2h');

await nft.removeAddress('1.2.3.4');
await nft.removeAddresses(['10.0.0.1', '10.0.0.2']);

await nft.deleteTable();
```

## API

### `new NftManager(options?)`

| Option | Type | Default | Description |
|---|---|---|---|
| `strategy` | `'drop' \| 'reject' \| 'tcp-reset'` | `'reject'` | How to handle packets from blacklisted IPs |

### Methods

All methods return `Promise<void>`.

| Method | Description |
|---|---|
| `createTable()` | Create IPv4/IPv6 tables with blacklist sets and filter chains. Idempotent. |
| `deleteTable()` | Delete both tables. Idempotent. |
| `addAddress(ip, timeout)` | Add IP to blacklist. Timeout: `"30s"`, `"10m"`, `"2h"`, `"7d"`. |
| `removeAddress(ip)` | Remove IP from blacklist. Idempotent. |
| `addAddresses(ips, timeout)` | Bulk add. Chunked for efficient netlink communication. |
| `removeAddresses(ips)` | Bulk remove. Idempotent. |

## Strategies

- **`drop`** — silently discard packets
- **`reject`** — respond with ICMP port-unreachable (default)
- **`tcp-reset`** — TCP RST for TCP traffic, ICMP reject for non-TCP

## Building from source

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install pkg-config libnftnl-dev libmnl-dev build-essential

# Build
npm run build

# Prebuild for current platform
npx prebuildify --napi --strip

# Prebuild for linux/amd64 + linux/arm64 via Docker
npm run prebuild:all
```

## License

AGPL-3.0-only
