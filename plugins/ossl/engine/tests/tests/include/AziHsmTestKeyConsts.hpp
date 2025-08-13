// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_TEST_KEY_CONSTS_HPP
#define AZIHSM_TEST_KEY_CONSTS_HPP

#include <stddef.h>
#include <vector>

extern const std::vector<unsigned char> RSA_PRIV_KEY_2048;
extern const std::vector<unsigned char> RSA_PRIV_KEY_3072;
extern const std::vector<unsigned char> RSA_PRIV_KEY_4096;
extern const std::vector<unsigned char> ECC_PRIV_KEY_PRIME256V1;
extern const std::vector<unsigned char> ECC_PRIV_KEY_PRIME256V1_2;
extern const std::vector<unsigned char> ECC_PRIV_KEY_SECP384R1;
extern const std::vector<unsigned char> ECC_PRIV_KEY_SECP384R1_2;
extern const std::vector<unsigned char> ECC_PRIV_KEY_SECP521R1;
extern const std::vector<unsigned char> ECC_PRIV_KEY_SECP521R1_2;

#endif // AZIHSM_TEST_KEY_CONSTS_HPP