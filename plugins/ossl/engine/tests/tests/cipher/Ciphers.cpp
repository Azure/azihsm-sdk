// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmCiphers.hpp"
#include <catch2/catch_test_macros.hpp>
#include <stdexcept>
#include <cstring>

// Common Ciphers test cases
TEST_CASE("AZIHSM Ciphers", "[AziHsmEngineCiphers]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    const EVP_CIPHER *cipher;

    SECTION("Test Query Supported NIDs of Ciphers")
    {
        const int *nids;
        ENGINE_CIPHERS_PTR ciphers_fn = ENGINE_get_ciphers(e);
        REQUIRE(ciphers_fn != nullptr);

        REQUIRE(ciphers_fn(e, nullptr, nullptr, 0) == -1);
        REQUIRE(ciphers_fn(e, nullptr, &nids, 0) == 5);
        REQUIRE(nids[0] == NID_aes_128_cbc);
        REQUIRE(nids[1] == NID_aes_192_cbc);
        REQUIRE(nids[2] == NID_aes_256_cbc);
        REQUIRE(nids[3] == NID_aes_256_gcm);
        REQUIRE(nids[4] == NID_aes_256_xts);
        REQUIRE(ciphers_fn(e, &cipher, nullptr, 0) == -1);
        REQUIRE(ciphers_fn(e, &cipher, nullptr, -1) == 0);
    }

    SECTION("Test Get AES Cipher by NID")
    {
        REQUIRE(AziHsmAesCipher(e, NID_aes_128_cbc, EVP_CIPH_CBC_MODE, 16).getCipher() != nullptr);
        REQUIRE(AziHsmAesCipher(e, NID_aes_192_cbc, EVP_CIPH_CBC_MODE, 16).getCipher() != nullptr);
        REQUIRE(AziHsmAesCipher(e, NID_aes_256_cbc, EVP_CIPH_CBC_MODE, 16).getCipher() != nullptr);
        REQUIRE(AziHsmAesCipher(e, NID_aes_256_gcm, EVP_CIPH_GCM_MODE, 12).getCipher() != nullptr);
        REQUIRE(AziHsmAesCipher(e, NID_aes_256_xts, EVP_CIPH_XTS_MODE, 16).getCipher() != nullptr);
    }

    SECTION("Test AES init ctx with multiple ciphers")
    {
        // Allocate ctx
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init CTX with AES-128-CBC
        REQUIRE(aes_ctx.init(e, NID_aes_128_cbc, 1, nullptr, nullptr) == 1);

        // Init Same CTX with AES-192-CBC
        REQUIRE(aes_ctx.init(e, NID_aes_192_cbc, 1, nullptr, nullptr) == 1);

        // Init Same CTX with AES-256-CBC
        REQUIRE(aes_ctx.init(e, NID_aes_256_cbc, 1, nullptr, nullptr) == 1);

        // Init Same CTX with AES-256-GCM
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);

        // Init Same CTX with AES-256-XTS
        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
    }

    SECTION("Test AES init ctx with multiple ciphers with IV")
    {
        // Allocate ctx
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        unsigned char iv[16] = {0};
        REQUIRE(RAND_bytes(iv, 16) == 1);

        unsigned char iv_gcm[12] = {0};
        REQUIRE(RAND_bytes(iv_gcm, 12) == 1);

        // Init CTX with AES-128-CBC
        REQUIRE(aes_ctx.init(e, NID_aes_128_cbc, 1, nullptr, iv) == 1);

        // Init Same CTX with AES-192-CBC
        REQUIRE(aes_ctx.init(e, NID_aes_192_cbc, 1, nullptr, iv) == 1);

        // Init Same CTX with AES-256-CBC
        REQUIRE(aes_ctx.init(e, NID_aes_256_cbc, 1, nullptr, iv) == 1);

        // Init Same CTX with AES-256-GCM
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, iv_gcm) == 1);

        // Init Same CTX with AES-256-XTS
        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, iv) == 1);
    }

    SECTION("Test AES init ctx with multiple keys")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init ctx for AES-128-CBC cipher and generate a new key
        REQUIRE(aes_ctx.init(e, NID_aes_128_cbc, 1, nullptr, nullptr) == 1);
        REQUIRE(aes_ctx.keygen(1) == 1);

        // Init ctx for AES-192-CBC cipher and generate a new key
        REQUIRE(aes_ctx.init(e, NID_aes_192_cbc, 1, nullptr, nullptr) == 1);
        REQUIRE(aes_ctx.keygen(1) == 1);

        // Init ctx for AES-256-CBC cipher and generate a new key
        REQUIRE(aes_ctx.init(e, NID_aes_256_cbc, 1, nullptr, nullptr) == 1);
        REQUIRE(aes_ctx.keygen(1) == 1);

        // Init ctx for AES-256-GCM cipher and generate a new key
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        REQUIRE(aes_ctx.keygen(1) == 1);

        // Init ctx for AES-256-XTS cipher and generate a new key
        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
        REQUIRE(aes_ctx.keygen(1) == 1);
    }
}
