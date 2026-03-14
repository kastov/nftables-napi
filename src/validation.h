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

// Parse IP string, validate via inet_pton, store binary form.
// Returns IpAddr with family=Invalid on failure.
[[nodiscard]] IpAddr parse_ip(const std::string& ip);

struct PortVal {
    uint16_t port;
    bool valid;
};

// Parse port number. Returns {port, valid=true} on success.
// Valid range: 0-65535.
[[nodiscard]] PortVal parse_port(double value);
