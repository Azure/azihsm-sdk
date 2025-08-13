// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_TEST_FLAGS_H
#define AZIHSM_TEST_FLAGS_H

#include "AziHsmEngine.hpp"
#include <openssl/evp.h>
#include <vector>
#include <stdlib.h>

// Used in a lot of hash tests
enum AziHsmHashTestFlag
{
    HASH_TEST_NORMAL = 0x0,

    TAMPERED_DGST = 0x1,
    TAMPERED_SIG = 0x2,
    INVALID_DGST_LEN = 0x4,
    INVALID_SIG_LEN = 0x8,
    SIGN_FAIL = 0x10,
    COPY_KEY = 0x20,
};

// Used in RSA tests
enum AziHsmRsaTestFlag
{
    RSA_TEST_NORMAL = 0x0,

    // Common test cases
    NEW_KEY = 0x1,
    TAMPER_CIPHER = 0x2,
    VERIFY_TWICE = 0x4,
    COPY_CTX = 0x8,
    INVALID_SIZE = 0x10,
    NON_MATCH_HASH = 0x100,
};

#define IS_FLAG(x, flag) (((unsigned int)(x) & (unsigned int)(flag)) != 0)

// Hash test macros
#define IS_TAMPERED_DGST(x) IS_FLAG((x), AziHsmHashTestFlag::TAMPERED_DGST)
#define IS_TAMPERED_SIG(x) IS_FLAG((x), AziHsmHashTestFlag::TAMPERED_SIG)
#define IS_INVALID_DGST_LEN(x) IS_FLAG((x), AziHsmHashTestFlag::INVALID_DGST_LEN)
#define IS_INVALID_SIG_LEN(x) IS_FLAG((x), AziHsmHashTestFlag::INVALID_SIG_LEN)
#define IS_SIGN_FAIL(x) IS_FLAG((x), AziHsmHashTestFlag::SIGN_FAIL)
#define IS_COPY_KEY(x) IS_FLAG((x), AziHsmHashTestFlag::COPY_KEY)

// RSA test macros
#define IS_NEW_KEY(x) (IS_FLAG((x), AziHsmRsaTestFlag::NEW_KEY))
#define IS_TAMPER_CIPHER(x) (IS_FLAG((x), AziHsmRsaTestFlag::TAMPER_CIPHER))
#define IS_VERIFY_TWICE(x) (IS_FLAG((x), AziHsmRsaTestFlag::VERIFY_TWICE))
#define IS_COPY_CTX(x) (IS_FLAG((x), AziHsmRsaTestFlag::COPY_CTX))
#define IS_INVALID_SIZE(x) (IS_FLAG((x), AziHsmRsaTestFlag::INVALID_SIZE))
#define IS_NON_MATCH_HASH(x) (IS_FLAG((x), AziHsmRsaTestFlag::NON_MATCH_HASH))

#endif // AZIHSM_TEST_FLAGS_H
