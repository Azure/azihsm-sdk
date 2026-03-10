// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_TEST_HASH_H
#define AZIHSM_TEST_HASH_H

#include "AziHsmEngine.hpp"
#include "AziHsmHash.hpp"
#include <openssl/evp.h>
#include <vector>
#include <stdlib.h>

std::vector<unsigned char> generate_random_vector(size_t size);
std::vector<unsigned char> generate_hash(AziHsmShaHashType hash_type, size_t size);

#endif // AZIHSM_TEST_HASH_H
