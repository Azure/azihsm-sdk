// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmCiphers.hpp"
#include "../../../api-interface/azihsm_engine.h"
#include <catch2/catch_test_macros.hpp>
#include <openssl/rand.h>

static void validate_aes_unwrap(AziHsmEngine &azihsm_engine, int nid, AziHsmDigestKind digest_kind)
{
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
    REQUIRE(unwrapping_key.size() > 0);

    // Determine key size based on NID
    size_t key_size = 32;
    if (nid == NID_aes_128_cbc)
        key_size = 16;
    else if (nid == NID_aes_192_cbc)
        key_size = 24;
    else if (nid == NID_aes_256_cbc || nid == NID_aes_256_gcm || nid == NID_aes_256_xts)
        key_size = 32;
    else
        REQUIRE(false); // Unsupported NID

    // Generate random key with determined size
    std::vector<unsigned char> aes_key(key_size);
    REQUIRE(RAND_bytes(aes_key.data(), aes_key.size()) == 1);

    std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, aes_key, digest_kind);
    REQUIRE(wrapped_blob.size() > 0);

    // Generate random IV
    std::vector<unsigned char> iv(16);
    REQUIRE(RAND_bytes(iv.data(), iv.size()) == 1);

    AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();
    REQUIRE(aes_ctx.init(e, nid, 1, nullptr, iv.data()) == 1);

    REQUIRE(azihsm_engine.unwrapAes(aes_ctx.getCtx(), nid, wrapped_blob, digest_kind) == 1);
}

static void validate_aes_xts_unwrap(AziHsmEngine &azihsm_engine, int nid, AziHsmDigestKind digest_kind)
{
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
    REQUIRE(unwrapping_key.size() > 0);

    // Generate random key
    std::vector<unsigned char> aes_key1(32);
    REQUIRE(RAND_bytes(aes_key1.data(), aes_key1.size()) == 1);

    std::vector<unsigned char> wrapped_blob_1 = azihsm_engine.wrapTargetKey(unwrapping_key, aes_key1, digest_kind);
    REQUIRE(wrapped_blob_1.size() > 0);

    // Generate random key2
    std::vector<unsigned char> aes_key2(32);
    REQUIRE(RAND_bytes(aes_key2.data(), aes_key2.size()) == 1);

    std::vector<unsigned char> wrapped_blob_2 = azihsm_engine.wrapTargetKey(unwrapping_key, aes_key2, digest_kind);
    REQUIRE(wrapped_blob_2.size() > 0);

    AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();
    REQUIRE(aes_ctx.init(e, nid, 1, nullptr, nullptr) == 1);

    REQUIRE(azihsm_engine.unwrapAesXts(aes_ctx.getCtx(), wrapped_blob_1, wrapped_blob_2, digest_kind) == 1);
}

TEST_CASE("AZIHSM AES Unwrap tests", "[AesKeyUnWrap]")
{
    AziHsmEngine azihsm_engine = get_test_engine();

    SECTION("Test AES Cbc key Unwrap with AZIHSM_DIGEST_SHA1")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1;
        validate_aes_unwrap(azihsm_engine, NID_aes_128_cbc, digest_kind);
        validate_aes_unwrap(azihsm_engine, NID_aes_192_cbc, digest_kind);
        validate_aes_unwrap(azihsm_engine, NID_aes_256_cbc, digest_kind);
#ifdef AZIHSM_GCM
        validate_aes_unwrap(azihsm_engine, NID_aes_256_gcm, digest_kind);
#endif
#ifdef AZIHSM_XTS
        validate_aes_xts_unwrap(azihsm_engine, NID_aes_256_xts, digest_kind);
#endif
    }

    SECTION("Test AES Cbc key Unwrap with AZIHSM_DIGEST_SHA256")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA256;
        validate_aes_unwrap(azihsm_engine, NID_aes_128_cbc, digest_kind);
        validate_aes_unwrap(azihsm_engine, NID_aes_192_cbc, digest_kind);
        validate_aes_unwrap(azihsm_engine, NID_aes_256_cbc, digest_kind);
#ifdef AZIHSM_GCM
        validate_aes_unwrap(azihsm_engine, NID_aes_256_gcm, digest_kind);
#endif
#ifdef AZIHSM_XTS
        validate_aes_xts_unwrap(azihsm_engine, NID_aes_256_xts, digest_kind);
#endif
    }

    SECTION("Test AES Cbc key Unwrap with AZIHSM_DIGEST_SHA384")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA384;
        validate_aes_unwrap(azihsm_engine, NID_aes_128_cbc, digest_kind);
        validate_aes_unwrap(azihsm_engine, NID_aes_192_cbc, digest_kind);
        validate_aes_unwrap(azihsm_engine, NID_aes_256_cbc, digest_kind);
#ifdef AZIHSM_GCM
        validate_aes_unwrap(azihsm_engine, NID_aes_256_gcm, digest_kind);
#endif
#ifdef AZIHSM_XTS
        validate_aes_xts_unwrap(azihsm_engine, NID_aes_256_xts, digest_kind);
#endif
    }

    SECTION("Test AES Cbc key Unwrap with AZIHSM_DIGEST_SHA512")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA512;
        validate_aes_unwrap(azihsm_engine, NID_aes_128_cbc, digest_kind);
        validate_aes_unwrap(azihsm_engine, NID_aes_192_cbc, digest_kind);
        validate_aes_unwrap(azihsm_engine, NID_aes_192_cbc, digest_kind);
#ifdef AZIHSM_GCM
        validate_aes_unwrap(azihsm_engine, NID_aes_256_gcm, digest_kind);
#endif
#ifdef AZIHSM_XTS
        validate_aes_xts_unwrap(azihsm_engine, NID_aes_256_xts, digest_kind);
#endif
    }
}
