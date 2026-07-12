#pragma once

#include <string>

struct [[nodiscard]] NlResult {
    bool success;
    std::string error;
    int error_code = 0;
};
