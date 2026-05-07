#pragma once

#include <array>
#include <cstdint>
#include <string>

enum class IpFamily {
    IPv4,
    IPv6,
    Invalid
};

struct IpAddr {
    IpFamily family = IpFamily::Invalid;
    std::array<uint8_t, 16> bytes{};
    uint32_t len = 0;
};

struct CidrAddr {
    IpAddr network;       // network address (e.g., 10.0.0.0)
    IpAddr end;           // exclusive end address (e.g., 11.0.0.0 for /8)
};

// Parse IP string or CIDR notation. Accepts:
//   "1.2.3.4"          -> CidrAddr{network=1.2.3.4, end=1.2.3.5}
//   "10.0.0.0/8"       -> CidrAddr{network=10.0.0.0, end=11.0.0.0}
//   "2001:db8::/32"    -> CidrAddr{network=2001:db8::, end=2001:db9::}
//   "198.19.0.0/15"    -> CidrAddr{network=198.18.0.0, end=198.20.0.0}
//                         (host bits silently masked off — see below)
//
// Misaligned CIDR (host bits set) is auto-normalized: host bits are
// masked off to obtain the network address. Matches `ip route` and
// Python ipaddress.ip_network(strict=False). Rejects only:
// /0 (too dangerous), prefix > family bits, malformed input.
// Returns CidrAddr with network.family=Invalid on failure.
[[nodiscard]] CidrAddr parse_ip_or_cidr(const std::string& input);

struct PortVal {
    uint16_t port;
    bool valid;
};

// Parse port number. Returns {port, valid=true} on success.
// Valid range: 0-65535.
[[nodiscard]] PortVal parse_port(double value);
