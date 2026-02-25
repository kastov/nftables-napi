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
IpAddr parse_ip(const std::string& ip);

// Convert timeout string (e.g. "10m", "30s", "2h", "7d") to milliseconds.
// Returns 0 on invalid input or overflow.
uint64_t parse_timeout_ms(const std::string& timeout);
