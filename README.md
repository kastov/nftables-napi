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
const { NftManager } = require("nftables-napi");

const nft = new NftManager({
  tableName: "tablename",
  blacklistSetName: "blacklist",
  droplistSetName: "droplist",
});

await nft.createTable();

// Add with timeout (seconds)
await nft.addAddress({ ip: "1.2.3.4", set: "blacklist", timeout: 1800 });
await nft.addAddress({ ip: "2001:db8::1", set: "blacklist", timeout: 3600 });

// Add permanent (no timeout)
await nft.addAddress({ ip: "5.6.7.8", set: "droplist" });

// Bulk add
await nft.addAddresses({ ips: ["10.0.0.1", "10.0.0.2"], set: "blacklist", timeout: 7200 });

// Remove
await nft.removeAddress({ ip: "1.2.3.4", set: "blacklist" });
await nft.removeAddresses({ ips: ["10.0.0.1", "10.0.0.2"], set: "blacklist" });

await nft.deleteTable();
```

## API

### `new NftManager(options)`

| Option             | Type     | Required | Description                                  |
| ------------------ | -------- | -------- | -------------------------------------------- |
| `tableName`        | `string` | Yes      | Base table name (IPv6 auto-appends `'6'`)    |
| `blacklistSetName` | `string` | Yes      | Blacklist set name (IPv6 auto-appends `'6'`) |
| `droplistSetName`  | `string` | Yes      | Droplist set name (IPv6 auto-appends `'6'`)  |

Log prefixes are auto-generated: `'{setName}: '` for each set.

### Methods

All methods return `Promise<void>`.

| Method                                 | Description                                                           |
| -------------------------------------- | --------------------------------------------------------------------- |
| `createTable()`                        | Create IPv4/IPv6 tables with blacklist and droplist sets. Idempotent. |
| `deleteTable()`                        | Delete both tables. Idempotent.                                       |
| `addAddress({ ip, set, timeout? })`    | Add IP to set. `timeout` in seconds, omit for permanent.              |
| `removeAddress({ ip, set })`           | Remove IP from set. Idempotent.                                       |
| `addAddresses({ ips, set, timeout? })` | Bulk add to set. Chunked for efficient netlink communication.         |
| `removeAddresses({ ips, set })`        | Bulk remove from set. Idempotent.                                     |

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
