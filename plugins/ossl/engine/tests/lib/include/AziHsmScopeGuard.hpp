// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_SCOPE_GUARD
#define AZIHSM_SCOPE_GUARD

#include <functional>

class ScopeGuard {
public:
    ScopeGuard(std::function<void()> fn) : fn(fn) {}
    ~ScopeGuard() {
        if (fn) {
            fn();
        }
    }

private:
    std::function<void()> fn;
};

#endif // AZIHSM_SCOPE_GUARD