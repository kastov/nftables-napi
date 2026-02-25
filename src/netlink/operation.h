#pragma once

#include "nl_result.h"

class NlSocket;

class NlOperation {
public:
    virtual ~NlOperation() = default;
    virtual NlResult execute(NlSocket& sock) = 0;
};
