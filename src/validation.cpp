#include "validation.h"

#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <utility>

IpAddr parse_ip(const std::string& ip) {
    IpAddr result;

    struct in_addr addr4;
    if (inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
        result.family = IpFamily::IPv4;
        std::memcpy(result.bytes.data(), &addr4, sizeof(addr4));
        result.len = sizeof(addr4);
        return result;
    }

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
        result.family = IpFamily::IPv6;
        std::memcpy(result.bytes.data(), &addr6, sizeof(addr6));
        result.len = sizeof(addr6);
        return result;
    }

    return result;
}

uint64_t parse_timeout_ms(const std::string& timeout) {
    if (timeout.empty() || timeout.size() < 2) return 0;

    // Lookup table: map unit character to millisecond multiplier.
    constexpr std::array<std::pair<char, uint64_t>, 4> units{{
        {'s', 1'000ULL},
        {'m', 60'000ULL},
        {'h', 3'600'000ULL},
        {'d', 86'400'000ULL},
    }};

    char unit = timeout.back();
    uint64_t multiplier = 0;
    for (const auto& [ch, ms] : units) {
        if (ch == unit) {
            multiplier = ms;
            break;
        }
    }
    if (multiplier == 0) return 0;

    uint64_t value = 0;
    for (std::size_t i = 0; i < timeout.size() - 1; ++i) {
        if (!std::isdigit(static_cast<unsigned char>(timeout[i]))) return 0;
        uint64_t digit = static_cast<uint64_t>(timeout[i] - '0');

        // Overflow check: value * 10 + digit > UINT64_MAX
        if (value > (UINT64_MAX - digit) / 10) return 0;
        value = value * 10 + digit;
    }

    if (value == 0) return 0;

    // Overflow check: value * multiplier > UINT64_MAX
    if (value > UINT64_MAX / multiplier) return 0;
    return value * multiplier;
}
