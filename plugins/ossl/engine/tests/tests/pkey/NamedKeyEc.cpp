// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmTestEc.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmPKeyEc.hpp"
#include <vector>

static void
verify_named_key_ecdsa(AziHsmEngine &azihsm_engine, const char *key_name, int curve_name, int md_type)
{
    ENGINE *e = azihsm_engine.getEngine();
    // 1. Unwrap a named test ECC key and free the EVP_PKEY_CTX. The key should persist in HSM.
    {
        AziHsmPKeyEcCtx priv_key_ctx = unwrap_test_ec_pkey_ctx_key(
            azihsm_engine, curve_name, false, AZIHSM_DIGEST_SHA1, key_name, AZIHSM_AVAILABILITY_APP);
        REQUIRE(priv_key_ctx.getCtx() != nullptr);
    }

    // 2. Reload the named key and validate sign/verify with HSM
    AziHsmPKey pkey(e, key_name, true);
    REQUIRE(pkey.getPKey() != nullptr);

    AziHsmPKeyEcCtx ecdsa_ctx(e, pkey.getPKey());
    std::string test_text = "This is a named key edcsa test";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    std::vector<unsigned char> signature;

    REQUIRE(compute_digest(md_type, message, digest) == 1);
    REQUIRE(ecdsa_ctx.sign(signature, digest) == 1);
    REQUIRE(ecdsa_ctx.verify(signature, digest) == 1);

    // 3. Get publickey (EC_POINT) from named key and verify with OpenSSL APIs only
    // 3.1 Get public key
    AziHsmEcKey key(EVP_PKEY_get1_EC_KEY(pkey.getPKey()));
    const EC_POINT *pubkey = key.getPublicKey();
    REQUIRE(pubkey != nullptr);

    // 3.2 Verify with OpenSSL APIs only
    ec_verify_with_ossl(curve_name, pubkey, signature, digest);

    // 4. Delete named key
    REQUIRE(azihsm_delete_key(e, key_name) == 1);
}

static void verify_named_key_ecdh(AziHsmEngine &azihsm_engine, int curve_type)
{
    ENGINE *e = azihsm_engine.getEngine();
    const char *alice_name = "42", *bob_name = "43";

    // 1. Unwrap named test ECC key and free the EVP_PKEY_CTX. The keys should persist in HSM.
    {
        AziHsmPKeyEcCtx alice_ecdh_ctx = unwrap_test_ec_pkey_ctx_key(
            azihsm_engine,
            curve_type,
            true,
            AZIHSM_DIGEST_SHA1,
            alice_name,
            AZIHSM_AVAILABILITY_APP);

        AziHsmPKeyEcCtx bob_paramgen_ctx(e, curve_type);
        AziHsmPKeyEcCtx bob_ecdh_ctx = unwrap_test_ec_pkey_ctx_key(
            azihsm_engine,
            curve_type,
            true,
            AZIHSM_DIGEST_SHA1,
            bob_name,
            AZIHSM_AVAILABILITY_APP, 1);
    }

    // 2. Re open the named key and validate ECDH with HSM
    AziHsmPKey alice_pkey(e, alice_name, true);
    REQUIRE(alice_pkey.getPKey() != nullptr);
    AziHsmPKeyEcCtx alice_ecdh_ctx(e, alice_pkey.getPKey(), false);

    AziHsmPKey bob_pkey(e, bob_name, true);
    REQUIRE(bob_pkey.getPKey() != nullptr);
    AziHsmPKeyEcCtx bob_ecdh_ctx(e, bob_pkey.getPKey(), false);

    // 2.1 Derive secrets
    AziHsmPKeyEcCtx alice_secret_ctx(azihsm_engine.getEngine(), alice_ecdh_ctx.getPKey());
    std::vector<unsigned char> alice_secret;
    REQUIRE(alice_secret_ctx.derive(alice_ecdh_ctx.getPKey(), alice_secret) == 1);

    AziHsmPKeyEcCtx bob_secret_ctx(azihsm_engine.getEngine(), bob_ecdh_ctx.getPKey());
    std::vector<unsigned char> bob_secret;
    REQUIRE(bob_secret_ctx.derive(bob_ecdh_ctx.getPKey(), bob_secret) == 1);

    REQUIRE(alice_secret != bob_secret);

    // Delete named keys then try retrieving
    EVP_PKEY *key;
    REQUIRE(azihsm_delete_key(e, alice_name) == 1);
    key = ENGINE_load_private_key(e, alice_name, nullptr, nullptr);
    REQUIRE(key == nullptr);

    REQUIRE(azihsm_delete_key(e, bob_name) == 1);
    key = ENGINE_load_private_key(e, bob_name, nullptr, nullptr);
    REQUIRE(key == nullptr);
}

TEST_CASE("AZIHSM EC named keys", "[AziHsmEngineECCNamedKeys]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    const char *name = "42";

    SECTION("Creating, deleting, and retrieving named key")
    {
        // Unwrap a named test ECC P-256 key and free the EVP_PKEY_CTX. The key should persist in HSM.
        {
            AziHsmPKeyEcCtx priv_key_ctx = unwrap_test_ec_pkey_ctx_key(
                azihsm_engine,
                NID_X9_62_prime256v1,
                false,
                AZIHSM_DIGEST_SHA1,
                name,
                AZIHSM_AVAILABILITY_APP);
            REQUIRE(priv_key_ctx.getCtx() != nullptr);
        }

        // Test key retrieval after deleting the EVP_PKEY_CTX
        {
            AziHsmPKey pkey(e, name);
            REQUIRE(pkey.getPKey() != nullptr);
        }

        // Delete named key then try retrieving. The key should not be found.
        REQUIRE(azihsm_delete_key(e, name) == 1);
        EVP_PKEY *key = ENGINE_load_private_key(e, name, nullptr, nullptr);
        REQUIRE(key == nullptr);
    }

    SECTION("Signing/verifying with a named key")
    {
        verify_named_key_ecdsa(azihsm_engine, name, NID_X9_62_prime256v1, NID_sha1);
        verify_named_key_ecdsa(azihsm_engine, name, NID_X9_62_prime256v1, NID_sha256);

        verify_named_key_ecdsa(azihsm_engine, name, NID_secp384r1, NID_sha1);
        verify_named_key_ecdsa(azihsm_engine, name, NID_secp384r1, NID_sha256);
        verify_named_key_ecdsa(azihsm_engine, name, NID_secp384r1, NID_sha384);

        verify_named_key_ecdsa(azihsm_engine, name, NID_secp521r1, NID_sha1);
        verify_named_key_ecdsa(azihsm_engine, name, NID_secp521r1, NID_sha256);
        verify_named_key_ecdsa(azihsm_engine, name, NID_secp521r1, NID_sha384);
        verify_named_key_ecdsa(azihsm_engine, name, NID_secp521r1, NID_sha512);
    }

    SECTION("ECDH with named keys")
    {
        verify_named_key_ecdh(azihsm_engine, NID_X9_62_prime256v1);

        verify_named_key_ecdh(azihsm_engine, NID_secp384r1);

        verify_named_key_ecdh(azihsm_engine, NID_secp521r1);
    }
}
