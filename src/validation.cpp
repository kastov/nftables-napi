#include "validation.h"

#include <arpa/inet.h>
#include <cmath>
#include <cstring>

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
