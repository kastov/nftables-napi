#include "validation.h"

#include <arpa/inet.h>
#include <cmath>
#include <cstring>

namespace {

// Parse IP string, validate via inet_pton, store binary form.
// Returns IpAddr with family=Invalid on failure.
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

// Big-endian increment by 1 with carry propagation.
void increment_ip(uint8_t* bytes, uint32_t len) {
    for (int i = static_cast<int>(len) - 1; i >= 0; --i) {
        if (++bytes[i] != 0) {
            return; // no carry
        }
    }
    // Full overflow (e.g., 255.255.255.255 + 1) — bytes wrap to all zeros.
}

// Compute exclusive end address from network + prefix_len.
// end = network address with host bits zeroed, then the prefix portion incremented.
// For /8 on 10.0.0.0: byte[0]=10, increment -> 11, rest stays 0 -> 11.0.0.0
void compute_cidr_end(const IpAddr& network, uint8_t prefix_len, IpAddr& end) {
    end.family = network.family;
    end.len = network.len;

    uint32_t full_bytes = prefix_len / 8;
    uint32_t remainder_bits = prefix_len % 8;

    // Copy prefix bytes
    for (uint32_t i = 0; i < full_bytes && i < network.len; ++i) {
        end.bytes[i] = network.bytes[i];
    }

    if (remainder_bits > 0 && full_bytes < network.len) {
        // Mask off host bits in the boundary byte
        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remainder_bits));
        end.bytes[full_bytes] = network.bytes[full_bytes] & mask;
    }

    // Zero all bytes after the prefix boundary
    uint32_t start_zero = full_bytes + (remainder_bits > 0 ? 1 : 0);
    for (uint32_t i = start_zero; i < network.len; ++i) {
        end.bytes[i] = 0;
    }

    // Increment the prefix portion to get the exclusive end.
    // We increment at bit position prefix_len. This is equivalent to adding
    // 1 to the (prefix_len)-bit number formed by the first prefix_len bits.
    if (remainder_bits > 0) {
        // The boundary byte has some prefix bits. We need to increment
        // at the bit position. Add (1 << (8 - remainder_bits)) to that byte,
        // with carry propagation into earlier bytes.
        uint8_t add_val = static_cast<uint8_t>(1 << (8 - remainder_bits));
        uint16_t carry = add_val;
        for (int i = static_cast<int>(full_bytes); i >= 0 && carry > 0; --i) {
            carry += end.bytes[i];
            end.bytes[i] = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
    } else {
        // Prefix ends on a byte boundary. Increment the last prefix byte
        // with carry into earlier bytes.
        if (full_bytes > 0) {
            uint16_t carry = 1;
            for (int i = static_cast<int>(full_bytes) - 1; i >= 0 && carry > 0; --i) {
                carry += end.bytes[i];
                end.bytes[i] = static_cast<uint8_t>(carry & 0xFF);
                carry >>= 8;
            }
        }
    }
}

} // namespace

CidrAddr parse_ip_or_cidr(const std::string& input) {
    CidrAddr result{};

    auto slash_pos = input.find('/');

    if (slash_pos == std::string::npos) {
        // Plain IP address
        IpAddr ip = parse_ip(input);
        if (ip.family == IpFamily::Invalid) {
            return result;
        }

        result.network = ip;

        // end = ip + 1
        result.end = ip;
        increment_ip(result.end.bytes.data(), result.end.len);
        return result;
    }

    // CIDR notation: "base/prefix"
    std::string base_str = input.substr(0, slash_pos);
    std::string prefix_str = input.substr(slash_pos + 1);

    // Reject empty prefix or non-numeric prefix
    if (prefix_str.empty()) {
        return result;
    }
    for (char c : prefix_str) {
        if (c < '0' || c > '9') {
            return result;
        }
    }

    // Manual parse — no exceptions needed (digits already validated above).
    // Reject prefix strings longer than 3 chars (max valid: "128").
    if (prefix_str.size() > 3) {
        return result;
    }
    int prefix = 0;
    for (char c : prefix_str) {
        prefix = prefix * 10 + (c - '0');
    }

    IpAddr ip = parse_ip(base_str);
    if (ip.family == IpFamily::Invalid) {
        return result;
    }

    uint8_t max_prefix = (ip.family == IpFamily::IPv4) ? 32 : 128;

    // Reject /0 (too dangerous) and prefix > max
    if (prefix < 1 || prefix > max_prefix) {
        return result;
    }

    auto prefix_len = static_cast<uint8_t>(prefix);

    // Mask off host bits silently — input like "10.0.0.5/24" becomes
    // "10.0.0.0/24", matching `ip route` and Python ipaddress(strict=False).
    uint32_t full_bytes = prefix_len / 8;
    uint32_t remainder_bits = prefix_len % 8;

    if (remainder_bits > 0 && full_bytes < ip.len) {
        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remainder_bits));
        ip.bytes[full_bytes] &= mask;
    }

    uint32_t start_zero = full_bytes + (remainder_bits > 0 ? 1 : 0);
    for (uint32_t i = start_zero; i < ip.len; ++i) {
        ip.bytes[i] = 0;
    }

    result.network = ip;

    compute_cidr_end(ip, prefix_len, result.end);
    return result;
}

PortVal parse_port(double value) {
    if (std::isnan(value) || value < 0.0 || value > 65535.0) {
        return {0, false};
    }
    double truncated = std::trunc(value);
    if (value != truncated) {
        return {0, false};  // reject fractional ports
    }
    return {static_cast<uint16_t>(truncated), true};
}
