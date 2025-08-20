// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmTestHash.hpp"
#include "AziHsmTestFlags.hpp"
#include "AziHsmTestRsa.hpp"
#include <catch2/catch_test_macros.hpp>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <memory>
#include <stdexcept>

#include "../../../api-interface/azihsm_engine.h"

AziHsmPKeyRsaCtx unwrap_test_rsa_pkey_ctx_key(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey target_key,
    AziHsmKeyUsage key_usage,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability)
{
    std::vector<unsigned char> wrapped_blob = wrap_test_rsa_key(azihsm_engine, target_key, digest_kind);

    AziHsmPKey pkey(EVP_PKEY_RSA);
    EVP_PKEY *key = pkey.getPKey();
    if (key == nullptr)
    {
        throw std::runtime_error("pkey is null");
    }
    AziHsmPKeyRsaCtx priv_key_ctx(key, azihsm_engine.getEngine());

    EVP_PKEY_CTX *ctx = priv_key_ctx.getCtx();
    if (ctx == nullptr)
    {
        throw std::runtime_error("priv key ctx is null");
    }

    if (azihsm_engine.unwrapPKeyRsa(ctx, key_usage, wrapped_blob, digest_kind, name, availability) != 1)
    {
        throw std::runtime_error("Failed to unwrap RSA key");
    }

    return priv_key_ctx;
}

// Common PKey test cases
TEST_CASE("AZIHSM PKEY RSA keygen", "[AziHsmPKeyRsaKeygen]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("PKEY RSA keygen")
    {
        auto evp_pkey_ctx_deleter = [](EVP_PKEY_CTX *ctx)
        { EVP_PKEY_CTX_free(ctx); };

        std::unique_ptr<EVP_PKEY_CTX, decltype(evp_pkey_ctx_deleter)>
            ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, e), evp_pkey_ctx_deleter);
        REQUIRE(ctx.get() != nullptr);
        EVP_PKEY *pkey = nullptr;

        // Should fail
        REQUIRE(EVP_PKEY_keygen_init(ctx.get()) <= 0);
        REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0);
        REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 3072) <= 0);
        REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 4096) <= 0);
        REQUIRE(EVP_PKEY_keygen(ctx.get(), &pkey) <= 0);
        REQUIRE(pkey == nullptr);
    }
}
