// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmPKeyEc.hpp"
#include "AziHsmTestEngine.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmTestEc.hpp"
#include <catch2/catch_test_macros.hpp>
#include <cstring>

static AziHsmPKeyEcCtx generate_ec_key(ENGINE *e, int curve_name, bool ecdh = false)
{
    AziHsmPKeyEcCtx azihsm_ec_keygen_ctx(e, curve_name);
    EVP_PKEY *pkey = azihsm_ec_keygen_ctx.keygen(ecdh);
    REQUIRE(pkey != nullptr);

    AziHsmPKey pkey_ec(pkey);
    AziHsmPKeyEcCtx azihsm_ec_key_ctx(e, pkey_ec.getPKey());
    return azihsm_ec_key_ctx;
}

static AziHsmPKeyEcCtx unwrap_test_ec_key(AziHsmEngine &azihsm_engine, int curve_name)
{
    return unwrap_test_ec_pkey_ctx_key(azihsm_engine, curve_name, false);
}

static AziHsmPKeyEcCtx get_key_ctx(AziHsmEngine &azihsm_engine, int curve_name, KeyType key_type)
{
    return (key_type == KeyType::KEYGEN) ? generate_ec_key(azihsm_engine.getEngine(), curve_name) : unwrap_test_ec_key(azihsm_engine, curve_name);
}

static void verify_signature_digest(AziHsmPKeyEcCtx &ctx, std::vector<unsigned char> digest, int curve_name)
{
    // Sign
    std::vector<unsigned char> signature;

    if (ctx.sign(signature, digest) != 1)
    {
        throw std::runtime_error("Could not sign with context");
    }

    if (signature.size() != curve_raw_signature_size(curve_name))
    {
        throw std::runtime_error("Signature size mismatch");
    }

    if (std::memcmp(signature.data(), digest.data(), digest.size()) == 0)
    {
        throw std::runtime_error("Signature is equivalent to digest");
    }

    // Verify
    if (ctx.verify(signature, digest) != 1)
    {
        throw std::runtime_error("Could not verify signature against digest");
    }
}

static int verify_ecdsa(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name, int md_nid)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKeyEcCtx azihsm_ec_key_ctx = get_key_ctx(azihsm_engine, curve_name, key_type);
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);

    REQUIRE(compute_digest(md_nid, message, digest) == 1);
    verify_signature_digest(azihsm_ec_key_ctx, digest, curve_name);

    return 1;
}

static int verify_ecdsa_copy_ctx(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name, int md_nid)
{
    AziHsmPKeyEcCtx azihsm_ec_key_ctx = get_key_ctx(azihsm_engine, curve_name, key_type);

    std::string test_text = "Please ensure no body tampers this message or you will be in trouble";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);

    REQUIRE(compute_digest(md_nid, message, digest) == 1);

    // Sign
    std::vector<unsigned char> signature;
    REQUIRE(azihsm_ec_key_ctx.sign(signature, digest) == 1);
    REQUIRE(signature.size() == curve_raw_signature_size(curve_name));
    REQUIRE(std::memcmp(signature.data(), digest.data(), digest.size()) != 0);

    // Verify
    REQUIRE(azihsm_ec_key_ctx.verify(signature, digest) == 1);

    // Copy context and verify
    AziHsmPKeyEcCtx azihsm_ec_key_ctx_copy = azihsm_ec_key_ctx.copy();
    REQUIRE(azihsm_ec_key_ctx_copy.verify(signature, digest) == 1);

    // Try to use the copied Ctx to derive shared secret
    AziHsmPKeyEcCtx key_2 = generate_ec_key(azihsm_engine.getEngine(), curve_name, true);
    AziHsmPKeyEcCtx key1_secret_ctx(azihsm_engine.getEngine(), azihsm_ec_key_ctx_copy.getPKey());
    std::vector<unsigned char> secret1;

    AziHsmPKeyEcCtx key2_secret_ctx(azihsm_engine.getEngine(), key_2.getPKey());
    std::vector<unsigned char> secret2;

    REQUIRE(key1_secret_ctx.derive(azihsm_ec_key_ctx_copy.getPKey(), secret1) == 0);
    REQUIRE(key2_secret_ctx.derive(key_2.getPKey(), secret2) == 0);

    return 1;
}

static int verify_ecdsa_tampered_dgst(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name, int md_nid)
{
    AziHsmPKeyEcCtx azihsm_ec_key_ctx = get_key_ctx(azihsm_engine, curve_name, key_type);

    std::vector<unsigned char> message(1024);
    REQUIRE(RAND_bytes(message.data(), message.size()) == 1);
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);

    REQUIRE(compute_digest(md_nid, message, digest) == 1);

    // Sign
    std::vector<unsigned char> signature;
    REQUIRE(azihsm_ec_key_ctx.sign(signature, digest) == 1);
    REQUIRE(signature.size() == curve_raw_signature_size(curve_name));
    REQUIRE(std::memcmp(signature.data(), digest.data(), digest.size()) != 0);

    // Verify
    REQUIRE(azihsm_ec_key_ctx.verify(signature, digest) == 1);

    // Tamper digest
    digest[0] ^= 0x01;
    REQUIRE(azihsm_ec_key_ctx.verify(signature, digest) == 0);

    return 1;
}

static int verify_ecdsa_tampered_signature(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name, int md_nid)
{
    AziHsmPKeyEcCtx azihsm_ec_key_ctx = get_key_ctx(azihsm_engine, curve_name, key_type);

    std::vector<unsigned char> message(2048);
    REQUIRE(RAND_bytes(message.data(), message.size()) == 1);
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);

    REQUIRE(compute_digest(md_nid, message, digest) == 1);

    // Sign
    std::vector<unsigned char> signature;
    REQUIRE(azihsm_ec_key_ctx.sign(signature, digest) == 1);
    REQUIRE(signature.size() == curve_raw_signature_size(curve_name));
    REQUIRE(std::memcmp(signature.data(), digest.data(), digest.size()) != 0);

    // Verify
    REQUIRE(azihsm_ec_key_ctx.verify(signature, digest) == 1);

    // Tamper signature
    signature[0] ^= 0x01;
    REQUIRE(azihsm_ec_key_ctx.verify(signature, digest) == 0);

    return 1;
}

static int verify_ecdsa_multi(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name, int md_nid, int times)
{
    AziHsmPKeyEcCtx azihsm_ec_key_ctx = get_key_ctx(azihsm_engine, curve_name, key_type);

    int msg_len = 1024;

    for (int i = 0; i < times; i++)
    {
        // Sign and verify
        std::vector<unsigned char> message(msg_len);
        REQUIRE(RAND_bytes(message.data(), message.size()) == 1);
        std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
        REQUIRE(compute_digest(md_nid, message, digest) == 1);
        verify_signature_digest(azihsm_ec_key_ctx, digest, curve_name);

        msg_len *= 2;
    }
    return 1;
}

static int verify_ecdsa_invalid_dgst_size(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name)
{
    AziHsmPKeyEcCtx azihsm_ec_key_ctx = get_key_ctx(azihsm_engine, curve_name, key_type);

    std::vector<unsigned char> signature;

    std::vector<unsigned char> digest(20);
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);
    verify_signature_digest(azihsm_ec_key_ctx, digest, curve_name);

    digest.resize(curve_dgst_len(curve_name));
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);
    verify_signature_digest(azihsm_ec_key_ctx, digest, curve_name);

    digest.resize(1);
    REQUIRE(azihsm_ec_key_ctx.sign(signature, digest) == 0);

    digest.resize(curve_dgst_len(curve_name) + 1);
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);
    REQUIRE(azihsm_ec_key_ctx.sign(signature, digest) == 0);

    digest.resize(curve_dgst_len(curve_name) - 1);
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);
    REQUIRE(azihsm_ec_key_ctx.sign(signature, digest) == 0);

    int len = next_allowed_curve(curve_name);
    if (len != 0)
    {
        digest.resize(len);
        REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);
        REQUIRE(azihsm_ec_key_ctx.sign(signature, digest) == 0);
    }

    digest.resize(0);
    REQUIRE(azihsm_ec_key_ctx.sign(signature, digest) == 0);

    return 1;
}

static int verify_ecdsa_invalid_signature_sizes(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name)
{
    AziHsmPKeyEcCtx azihsm_ec_key_ctx = get_key_ctx(azihsm_engine, curve_name, key_type);

    std::vector<unsigned char> signature;

    std::vector<unsigned char> digest(20);
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    REQUIRE(azihsm_ec_key_ctx.sign(signature, digest) == 1);
    REQUIRE(signature.size() == curve_raw_signature_size(curve_name));
    REQUIRE(std::memcmp(signature.data(), digest.data(), digest.size()) != 0);
    REQUIRE(azihsm_ec_key_ctx.verify(signature, digest) == 1);

    std::vector<unsigned char> signature_copy = signature;
    int sig_len = signature.size();

    // truncate signature
    signature_copy.resize(sig_len - 1);
    REQUIRE(azihsm_ec_key_ctx.verify(signature_copy, digest) == 0);

    // extend signature with random bytes
    signature_copy = signature;
    signature_copy.resize(sig_len + 8);
    REQUIRE(RAND_bytes(signature_copy.data() + sig_len, 8) == 1);
    REQUIRE(azihsm_ec_key_ctx.verify(signature_copy, digest) == 0);

    return 1;
}

TEST_CASE("AZIHSM PKEY ECDSA", "[AziHsmPkeyEcdsa]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("ECDSA")
    {
        REQUIRE(verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha1) == 1);

        REQUIRE(verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha256) == 1);

        REQUIRE(verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha384) == 1);

        REQUIRE(verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha512) == 1);
        REQUIRE(verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha512) == 1);
    }

    SECTION("ECDSA copy ctx")
    {
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha1) == 1);

        REQUIRE(verify_ecdsa_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha256) == 1);

        REQUIRE(verify_ecdsa_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha384) == 1);

        REQUIRE(verify_ecdsa_copy_ctx(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha512) == 1);
        REQUIRE(verify_ecdsa_copy_ctx(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha512) == 1);
    }

    SECTION("ECDSA with tampered dgst ")
    {
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha1) == 1);

        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha256) == 1);

        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha384) == 1);

        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha512) == 1);
        REQUIRE(verify_ecdsa_tampered_dgst(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha512) == 1);
    }

    SECTION("ECDSA with tampered signature")
    {
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha1) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha1) == 1);

        REQUIRE(verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha256) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha256) == 1);

        REQUIRE(verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha384) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha384) == 1);

        REQUIRE(verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha512) == 1);
        REQUIRE(verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha512) == 1);
    }

    SECTION("ECDSA multiple times")
    {
        REQUIRE(verify_ecdsa_multi(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha1, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha1, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha1, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha1, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha1, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha1, 2) == 1);

        REQUIRE(verify_ecdsa_multi(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, NID_sha256, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, NID_sha256, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha256, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha256, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha256, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha256, 2) == 1);

        REQUIRE(verify_ecdsa_multi(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, NID_sha384, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, NID_sha384, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha384, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha384, 2) == 1);

        REQUIRE(verify_ecdsa_multi(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, NID_sha512, 2) == 1);
        REQUIRE(verify_ecdsa_multi(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, NID_sha512, 2) == 1);
    }

    SECTION("ECDSA invalid digest sizes")
    {
        REQUIRE(verify_ecdsa_invalid_dgst_size(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1) == 1);
        REQUIRE(verify_ecdsa_invalid_dgst_size(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1) == 1);

        REQUIRE(verify_ecdsa_invalid_dgst_size(KeyType::KEYGEN, azihsm_engine, NID_secp384r1) == 1);
        REQUIRE(verify_ecdsa_invalid_dgst_size(KeyType::UNWRAP, azihsm_engine, NID_secp384r1) == 1);

        REQUIRE(verify_ecdsa_invalid_dgst_size(KeyType::KEYGEN, azihsm_engine, NID_secp521r1) == 1);
        REQUIRE(verify_ecdsa_invalid_dgst_size(KeyType::UNWRAP, azihsm_engine, NID_secp521r1) == 1);
    }

    SECTION("ECDSA invalid signature sizes")
    {
        REQUIRE(verify_ecdsa_invalid_signature_sizes(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1) == 1);
        REQUIRE(verify_ecdsa_invalid_signature_sizes(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1) == 1);

        REQUIRE(verify_ecdsa_invalid_signature_sizes(KeyType::KEYGEN, azihsm_engine, NID_secp384r1) == 1);
        REQUIRE(verify_ecdsa_invalid_signature_sizes(KeyType::UNWRAP, azihsm_engine, NID_secp384r1) == 1);

        REQUIRE(verify_ecdsa_invalid_signature_sizes(KeyType::KEYGEN, azihsm_engine, NID_secp521r1) == 1);
        REQUIRE(verify_ecdsa_invalid_signature_sizes(KeyType::UNWRAP, azihsm_engine, NID_secp521r1) == 1);
    }
}
