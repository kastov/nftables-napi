#pragma once

#include <string>

struct [[nodiscard]] NlResult {
    bool success;
    std::string error;
};
