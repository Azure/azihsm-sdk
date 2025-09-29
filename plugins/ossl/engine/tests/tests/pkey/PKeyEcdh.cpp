// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmPKeyEc.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmTestEngine.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmTestEc.hpp"
#include <catch2/catch_test_macros.hpp>

static AziHsmPKeyEcCtx generate_ec_key(ENGINE *e, int curve_name, bool ecdh = true, bool useparam = true)
{
    AziHsmPKeyEcCtx azihsm_ec_keygen_ctx(e, curve_name);
    EVP_PKEY *pkey = azihsm_ec_keygen_ctx.keygen(useparam, ecdh); // ecdh = true for derivable, false for sign/verify
    REQUIRE(pkey != nullptr);

    AziHsmPKey pkey_ec(pkey);

    AziHsmPKeyEcCtx azihsm_ec_key_ctx(e, pkey_ec.getPKey());
    return azihsm_ec_key_ctx;
}

static AziHsmPKeyCtx unwrap_rsa_key(AziHsmEngine &azihsm_engine, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1)
{
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
    REQUIRE(unwrapping_key.size() > 0);

    std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, RSA_PRIV_KEY_2048, digest_kind);
    REQUIRE(wrapped_blob.size() > 0);

    AziHsmPKey pkey(EVP_PKEY_RSA);
    EVP_PKEY *key = pkey.getPKey();
    REQUIRE(key != nullptr);
    AziHsmPKeyCtx priv_key_ctx(key, e);

    EVP_PKEY_CTX *ctx = priv_key_ctx.getCtx();
    REQUIRE(ctx != nullptr);
    REQUIRE(azihsm_engine.unwrapPKeyRsa(ctx, AZIHSM_KEY_USAGE_SIGN_VERIFY, wrapped_blob, digest_kind) == 1);

    return priv_key_ctx;
}

static AziHsmPKeyEcCtx unwrap_test_ec_key(AziHsmEngine &azihsm_engine, int curve_name, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1, int test_key_num = 0)
{
    return unwrap_test_ec_pkey_ctx_key(azihsm_engine, curve_name, true, digest_kind, nullptr, AZIHSM_AVAILABILITY_SESSION, test_key_num);
}

int verify_ecdh(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1, bool ecdh = true)
{
    // 1. Generate Alice's and Bob's EC Keys based on the ecdh flag
    AziHsmPKeyEcCtx alice_ecdh_ctx = (key_type == KeyType::KEYGEN) ? generate_ec_key(azihsm_engine.getEngine(), curve_name, ecdh)
                                                                   : unwrap_test_ec_key(azihsm_engine, curve_name, digest_kind);

    AziHsmPKeyEcCtx bob_ecdh_ctx = (key_type == KeyType::KEYGEN) ? generate_ec_key(azihsm_engine.getEngine(), curve_name, ecdh)
                                                                 : unwrap_test_ec_key(azihsm_engine, curve_name, digest_kind, 1);

    // 2. Attempt to derive shared secrets
    AziHsmPKeyEcCtx alice_secret_ctx(azihsm_engine.getEngine(), alice_ecdh_ctx.getPKey());
    std::vector<unsigned char> alice_secret;

    AziHsmPKeyEcCtx bob_secret_ctx(azihsm_engine.getEngine(), bob_ecdh_ctx.getPKey());
    std::vector<unsigned char> bob_secret;

    alice_secret_ctx.derive(bob_ecdh_ctx.getPKey(), alice_secret);
    bob_secret_ctx.derive(alice_ecdh_ctx.getPKey(), bob_secret);

    if (ecdh)
    {
        REQUIRE(alice_secret != bob_secret);
    }
    return 1;
}

int verify_ecdh_copy_ctx(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1, bool ecdh = true)
{
    // 1. Generate Alice's and Bob's EC Keys based on the ecdh flag
    AziHsmPKeyEcCtx alice_ecdh_ctx = (key_type == KeyType::KEYGEN) ? generate_ec_key(azihsm_engine.getEngine(), curve_name, ecdh)
                                                                   : unwrap_test_ec_key(azihsm_engine, curve_name, digest_kind);

    AziHsmPKeyEcCtx bob_ecdh_ctx = (key_type == KeyType::KEYGEN) ? generate_ec_key(azihsm_engine.getEngine(), curve_name, ecdh)
                                                                 : unwrap_test_ec_key(azihsm_engine, curve_name, digest_kind, 1);
    // 2. Attempt to derive shared secrets with Alice's and Bob's EC keys and a copy of Bob's EC key
    AziHsmPKeyEcCtx alice_secret_ctx(azihsm_engine.getEngine(), alice_ecdh_ctx.getPKey());
    std::vector<unsigned char> alice_secret;

    AziHsmPKeyEcCtx bob_secret_ctx(azihsm_engine.getEngine(), bob_ecdh_ctx.getPKey());
    std::vector<unsigned char> bob_secret;

    alice_secret_ctx.derive(bob_ecdh_ctx.getPKey(), alice_secret);
    bob_secret_ctx.derive(alice_ecdh_ctx.getPKey(), bob_secret);

    // 3. Create a copy of Bob's EVP_PKEY_CTX which can only be used for ECDH
    AziHsmPKeyEcCtx bob_copy_secret_ctx = bob_secret_ctx.copy();
    std::vector<unsigned char> bob_copy_secret;
    bob_copy_secret_ctx.derive(alice_ecdh_ctx.getPKey(), bob_copy_secret);

    if (ecdh)
    {
        REQUIRE(alice_secret != bob_secret);
        REQUIRE(alice_secret != bob_copy_secret);
        REQUIRE(bob_secret != bob_copy_secret);
    }

    // 4. Attempt to sign with the copied context which should fail
    std::string test_text = "You should not be able to sign this message with an ECDH key";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    std::vector<unsigned char> signature;

    REQUIRE(compute_digest(NID_sha1, message, digest) == 1);
    REQUIRE(bob_copy_secret_ctx.sign(signature, digest) == 0);

    return 1;
}

int verify_ecdh_with_rsa_and_ecc(AziHsmEngine &azihsm_engine, int curve_name, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1)
{
    //  Generate Alice's RSA unwrapping key (non-ECC key)
    AziHsmPKeyCtx alice_rsa_ctx = unwrap_rsa_key(azihsm_engine, digest_kind); 

    //  Generate Bob's ECC key
    AziHsmPKeyEcCtx bob_ecc_ctx = generate_ec_key(azihsm_engine.getEngine(), curve_name);

    // Attempt to derive shared secrets
    AziHsmPKeyCtx alice_secret_ctx(alice_rsa_ctx.getPKey(), azihsm_engine.getEngine());
    std::vector<unsigned char> alice_secret;

    AziHsmPKeyEcCtx bob_secret_ctx(azihsm_engine.getEngine(), bob_ecc_ctx.getPKey());
    std::vector<unsigned char> bob_secret;

    return alice_secret_ctx.derive(bob_ecc_ctx.getPKey(), alice_secret);
}

int verify_ecdh_with_non_ecc_key(AziHsmEngine &azihsm_engine, int alice_curve)
{
    //  Generate Alice's ECC key
    AziHsmPKeyEcCtx alice_ec_key = generate_ec_key(azihsm_engine.getEngine(), alice_curve);

    // Generate Bob's RSA (non-ECC) key
    AziHsmPKeyCtx bob_rsa_ctx = unwrap_rsa_key(azihsm_engine);

    // Attempt to derive shared secrets with Alice's ECC private key and Bob's RSA public key
    AziHsmPKeyEcCtx alice_secret_ctx(azihsm_engine.getEngine(), alice_ec_key.getPKey());
    std::vector<unsigned char> alice_secret;

    // Attempt ECDH derivation with Alice's EC private key and Bob's RSA public key
    return alice_secret_ctx.derive(bob_rsa_ctx.getPKey(), alice_secret);
}

int verify_ecdh_with_mismatched_curves(AziHsmEngine &azihsm_engine, int alice_curve, int bob_curve)
{
    // 1. Generate Alice's ECC key on her curve (e.g., P-256)
    AziHsmPKeyEcCtx alice_ec_key = generate_ec_key(azihsm_engine.getEngine(), alice_curve);

    // 2. Generate Bob's ECC key on a different curve (e.g., P-384)
    AziHsmPKeyEcCtx bob_ec_key = generate_ec_key(azihsm_engine.getEngine(), bob_curve);

    // Attempt to derive shared secrets with Alice's ECC private key and Bob's ECC public key from a different curve
    AziHsmPKeyEcCtx alice_secret_ctx(azihsm_engine.getEngine(), alice_ec_key.getPKey());
    std::vector<unsigned char> alice_secret;

    // Attempt ECDH derivation with mismatched curves
    alice_secret_ctx.derive(bob_ec_key.getPKey(), alice_secret);
    return 1;
}

TEST_CASE("AZIHSM PKEY ECDH", "[AziHsmPkeyEcdh]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("ECDH High Level (X9_62_prime256v1)")
    {
        REQUIRE(verify_ecdh(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA1) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA256) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA384) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA512) == 1);
    }

    SECTION("ECDH high level (secp384r1)")
    {
        REQUIRE(verify_ecdh(KeyType::KEYGEN, azihsm_engine, NID_secp384r1) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA1) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA256) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA384) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA512) == 1);
    }

    SECTION("ECDH High level (secp521r1)")
    {

        REQUIRE(verify_ecdh(KeyType::KEYGEN, azihsm_engine, NID_secp521r1) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA1) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA256) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA384) == 1);
        REQUIRE(verify_ecdh(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA512) == 1);
    }

    SECTION("ECDH Copy Context (X9_62_prime256v1)")
    {
        REQUIRE(verify_ecdh_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA1) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA256) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA384) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA512) == 1);
    }

    SECTION("ECDH Copy Context (secp384r1)")
    {
        REQUIRE(verify_ecdh_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_secp384r1) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA1) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA256) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA384) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA512) == 1);
    }

    SECTION("ECDH Copy Context (secp521r1)")
    {
        REQUIRE(verify_ecdh_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_secp521r1) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA1) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA256) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA384) == 1);
        REQUIRE(verify_ecdh_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA512) == 1);
    }

    SECTION("ECDH with non-derive sign/verify ECC keys")
    {
        REQUIRE(verify_ecdh(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA1, false) == 1);
        REQUIRE(verify_ecdh(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA1, false) == 1);
        REQUIRE(verify_ecdh(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA1, false) == 1);
    }

    SECTION("ECDH with Mismatched ECC Curves")
    {
        REQUIRE(verify_ecdh_with_mismatched_curves(azihsm_engine, NID_X9_62_prime256v1, NID_secp384r1) == 1);
        REQUIRE(verify_ecdh_with_mismatched_curves(azihsm_engine, NID_X9_62_prime256v1, NID_secp521r1) == 1);
        REQUIRE(verify_ecdh_with_mismatched_curves(azihsm_engine, NID_secp384r1, NID_X9_62_prime256v1) == 1);
        REQUIRE(verify_ecdh_with_mismatched_curves(azihsm_engine, NID_X9_62_prime256v1, NID_secp521r1) == 1);
        REQUIRE(verify_ecdh_with_mismatched_curves(azihsm_engine, NID_secp521r1, NID_secp384r1) == 1);
        REQUIRE(verify_ecdh_with_mismatched_curves(azihsm_engine, NID_secp521r1, NID_X9_62_prime256v1) == 1);
    }

    SECTION("ECDH with ecc private key and Non-ECC Public Key")
    {
        REQUIRE(verify_ecdh_with_non_ecc_key(azihsm_engine, NID_X9_62_prime256v1) == 0);
        REQUIRE(verify_ecdh_with_non_ecc_key(azihsm_engine, NID_secp384r1) == 0);
        REQUIRE(verify_ecdh_with_non_ecc_key(azihsm_engine, NID_secp521r1) == 0);
    }

    SECTION("ECDH with non ECC keys")
    {
        REQUIRE(verify_ecdh_with_rsa_and_ecc(azihsm_engine, NID_X9_62_prime256v1, AZIHSM_DIGEST_SHA1) == 0);
        REQUIRE(verify_ecdh_with_rsa_and_ecc(azihsm_engine, NID_secp384r1, AZIHSM_DIGEST_SHA1) == 0);
        REQUIRE(verify_ecdh_with_rsa_and_ecc(azihsm_engine, NID_secp521r1, AZIHSM_DIGEST_SHA1) == 0);
    }
}
