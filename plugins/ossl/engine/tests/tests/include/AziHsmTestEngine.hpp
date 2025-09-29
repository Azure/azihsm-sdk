// Copyright (c) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_TEST_ENGINE_HPP
#define AZIHSM_TEST_ENGINE_HPP

#include "AziHsmEngine.hpp"
#include <vector>
#include <openssl/engine.h>
#include <catch2/catch_test_macros.hpp>

extern const char *ENGINE_ID;
extern const char *ENGINE_SO_DIR;
extern const char *ENGINE_SO_NAME;

AziHsmEngine get_test_engine(const char *so_dir = ENGINE_SO_DIR, const char *so_name = ENGINE_SO_NAME, const char *engine_id = ENGINE_ID);

#endif // AZIHSM_TEST_ENGINE_HPP