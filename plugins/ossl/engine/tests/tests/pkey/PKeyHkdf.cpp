// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmEc.hpp"
#include "AziHsmPKeyEc.hpp"
#include "AziHsmPKeyHkdf.hpp"
#include "AziHsmCiphers.hpp"
#include <catch2/catch_test_macros.hpp>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <cstring>

static int derive_secret_low_level(ENGINE *e, int nid, std::vector<unsigned char> &alice_secret, std::vector<unsigned char> &bob_secret)
{
    AziHsmEcKey alice_ec_key(e);
    if (alice_ec_key.keygen(nid, true) != 1)
    {
        return 0;
    }

    const EC_POINT *alice_pubkey = alice_ec_key.getPublicKey();

    AziHsmEcKey bob_ec_key(e);
    if (bob_ec_key.keygen(nid, true) != 1)
    {
        return 0;
    }
    const EC_POINT *bob_pubkey = bob_ec_key.getPublicKey();

    int alice_secret_size = alice_ec_key.getSharedSecretSize();
    if (ECDH_compute_key(
            alice_secret.data(),
            alice_secret_size,
            bob_pubkey,
            alice_ec_key.getKey(),
            nullptr) != 8)
    {
        return 0;
    }

    int bob_secret_size = bob_ec_key.getSharedSecretSize();
    if (ECDH_compute_key(
            bob_secret.data(),
            bob_secret_size,
            alice_pubkey,
            bob_ec_key.getKey(),
            nullptr) != 8)
    {
        return 0;
    }

    alice_secret.resize(8);
    bob_secret.resize(8);
    return 1;
}

static int derive_secret_high_level(ENGINE *e, int curve_name, std::vector<unsigned char> &alice_secret, std::vector<unsigned char> &bob_secret)
{
    // 1. Generate alice's and Bob's EC Key
    AziHsmPKeyEcCtx alice_keygen_ctx(e, curve_name);
    EVP_PKEY *alice_pkey_ptr = alice_keygen_ctx.keygen(true, true);
    if (alice_pkey_ptr == nullptr)
    {
        return 0;
    }
    AziHsmPKey alice_pkey(alice_pkey_ptr);

    AziHsmPKeyEcCtx bob_keygen_ctx(e, curve_name);
    EVP_PKEY *bob_pkey_ptr = bob_keygen_ctx.keygen(true, true);
    if (bob_pkey_ptr == nullptr)
    {
        return 0;
    }
    AziHsmPKey bob_pkey(bob_pkey_ptr);

    // 2. Derive shared secret
    AziHsmPKeyEcCtx alice_secret_ctx(e, alice_pkey.getPKey());
    AziHsmPKeyEcCtx bob_secret_ctx(e, bob_pkey.getPKey());

    if (alice_secret_ctx.derive(bob_pkey.getPKey(), alice_secret) != 1 || bob_secret_ctx.derive(alice_pkey.getPKey(), bob_secret) != 1)
    {
        return 0;
    }

    return 1;
}

static int verify_enc_dec(std::vector<unsigned char> alice_key, std::vector<unsigned char> alice_msg,
                          std::vector<unsigned char> bob_key, std::vector<unsigned char> bob_msg, ENGINE *e, int nid)
{
    AziHsmAesCipherCtx alice_aes_ctx = AziHsmAesCipherCtx();
    AziHsmAesCipherCtx bob_aes_ctx = AziHsmAesCipherCtx();

    // Send message from Alice to Bob
    REQUIRE(alice_aes_ctx.init(e, nid, 1, alice_key.data(), nullptr) == 1); // init for encryption
    REQUIRE(bob_aes_ctx.init(e, nid, 0, bob_key.data(), nullptr) == 1);     // init for decryption

    REQUIRE(EVP_CIPHER_CTX_iv_length(alice_aes_ctx.getCtx()) == EVP_CIPHER_CTX_iv_length(bob_aes_ctx.getCtx()));
    int iv_len = EVP_CIPHER_CTX_iv_length(alice_aes_ctx.getCtx());

    std::vector<unsigned char> common_iv(iv_len);
    REQUIRE(RAND_bytes(common_iv.data(), iv_len) == 1);

    int alice_msg_len = alice_msg.size();
    std::vector<unsigned char> bob_cipher_text;
    std::vector<unsigned char> bob_recovered_text;

    REQUIRE(alice_aes_ctx.encrypt(alice_msg.data(), alice_msg_len, common_iv.data(), bob_cipher_text) == 1);
    REQUIRE(bob_aes_ctx.decrypt(bob_cipher_text.data(), bob_cipher_text.size(), common_iv.data(), bob_recovered_text) == 1);
    REQUIRE(std::memcmp(alice_msg.data(), bob_recovered_text.data(), alice_msg_len) == 0);

    // Send message from Bob to Alice
    REQUIRE(bob_aes_ctx.init(e, nid, 1, bob_key.data(), nullptr) == 1);     // init for encryption
    REQUIRE(alice_aes_ctx.init(e, nid, 0, alice_key.data(), nullptr) == 1); // init for decryption

    REQUIRE(EVP_CIPHER_CTX_iv_length(alice_aes_ctx.getCtx()) == EVP_CIPHER_CTX_iv_length(bob_aes_ctx.getCtx()));
    int alice_iv_len = EVP_CIPHER_CTX_iv_length(alice_aes_ctx.getCtx());
    REQUIRE(alice_iv_len == iv_len);

    int bob_msg_len = bob_msg.size();
    std::vector<unsigned char> alice_cipher_text;
    std::vector<unsigned char> alice_recovered_text;

    REQUIRE(alice_aes_ctx.encrypt(bob_msg.data(), bob_msg_len, common_iv.data(), alice_cipher_text) == 1);
    REQUIRE(bob_aes_ctx.decrypt(alice_cipher_text.data(), alice_cipher_text.size(), common_iv.data(), alice_recovered_text) == 1);
    REQUIRE(std::memcmp(bob_msg.data(), alice_recovered_text.data(), bob_msg_len) == 0);

    return 1;
}

static int testKeyDerivation(ENGINE *e, int curve_name, int key_type, int md, bool high_level = false, bool use_hkdf = false)
{
    // Get the secret size based on the curve
    int secret_size = AziHsmHkdf::getSecretSize(curve_name);
    std::vector<unsigned char> alice_secret(secret_size);
    std::vector<unsigned char> bob_secret(secret_size);

    // Perform ECDH key exchange
    if (high_level)
    {
        REQUIRE(derive_secret_high_level(e, curve_name, alice_secret, bob_secret) == 1);
    }
    else
    {
        REQUIRE(derive_secret_low_level(e, curve_name, alice_secret, bob_secret) == 1);
    }
    REQUIRE(alice_secret != bob_secret);

    // Set up parameters specific to HKDF or KBKDF
    std::vector<unsigned char> param1;
    std::vector<unsigned char> param2;

    if (use_hkdf) // HKDF requires salt and info
    {
        param1.resize(EVP_MD_size(EVP_get_digestbynid(md))); // Salt
        REQUIRE(RAND_bytes(param1.data(), param1.size()) == 1);

        param2.resize(16); // Info
        REQUIRE(RAND_bytes(param2.data(), param2.size()) == 1);
    }
    else // KBKDF requires label and context
    {
        param1.resize(16); // Label
        REQUIRE(RAND_bytes(param1.data(), param1.size()) == 1);

        param2.resize(16); // Context
        REQUIRE(RAND_bytes(param2.data(), param2.size()) == 1);
    }

    // Initialize contexts for Alice and Bob with HKDF or KBKDF settings
    AziHsmHkdf alice_ctx = AziHsmHkdf(e, alice_secret, key_type, md, use_hkdf);
    AziHsmHkdf bob_ctx = AziHsmHkdf(e, bob_secret, key_type, md, use_hkdf);

    std::vector<unsigned char> alice_key(alice_ctx.getAesKeyLen());
    std::vector<unsigned char> bob_key(bob_ctx.getAesKeyLen());

    if (use_hkdf) // Perform HKDF derivation
    {
        alice_ctx.derive(param1, param2, alice_key);
        bob_ctx.derive(param1, param2, bob_key);
    }
    else // Perform KBKDF derivation
    {
        alice_ctx.derive(param1, param2, alice_key);
        bob_ctx.derive(param1, param2, bob_key);
    }

    REQUIRE(alice_key != bob_key);

    // Message exchange verification
    std::string alice_txt = use_hkdf ? "Hey, Bob! What's the secret?" : "Hey, Bob! Let's switch to KBKDF!";
    std::string bob_txt = use_hkdf ? "Hey, Alice! The secret is in the key!" : "Hey, Alice! You got it!";
    std::vector<unsigned char> alice_msg(alice_txt.begin(), alice_txt.end());
    std::vector<unsigned char> bob_msg(bob_txt.begin(), bob_txt.end());

    REQUIRE(verify_enc_dec(alice_key, alice_msg, bob_key, bob_msg, e, key_type) == 1);

    return 1;
}

TEST_CASE("AZIHSM PKEY HKDF", "[AziHsmHkdf]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    AziHsmEcKeyMethod azihsm_ec_key_method(e);

    SECTION("HKDF set MD")
    {
        AziHsmHkdf ctx = AziHsmHkdf(e);

        REQUIRE(EVP_PKEY_derive_init(ctx.getCtx()) == 1);
        REQUIRE(EVP_PKEY_CTX_set_hkdf_md(ctx.getCtx(), EVP_sha256()) == 1);
        REQUIRE(EVP_PKEY_CTX_set_hkdf_md(ctx.getCtx(), EVP_sha384()) == 1);
        REQUIRE(EVP_PKEY_CTX_set_hkdf_md(ctx.getCtx(), EVP_sha512()) == 1);
        REQUIRE(EVP_PKEY_CTX_set_hkdf_md(ctx.getCtx(), EVP_sha1()) == 0);
    }

    SECTION("HKDF set salt")
    {
        AziHsmHkdf ctx = AziHsmHkdf(e);
        std::vector<unsigned char> salt_32(32);
        REQUIRE(RAND_bytes(salt_32.data(), salt_32.size()) == 1);

        std::vector<unsigned char> salt_64(32);
        REQUIRE(RAND_bytes(salt_64.data(), salt_64.size()) == 1);

        std::vector<unsigned char> salt_65(65);
        REQUIRE(RAND_bytes(salt_65.data(), salt_65.size()) == 1);

        REQUIRE(EVP_PKEY_derive_init(ctx.getCtx()) == 1);
        REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(ctx.getCtx(), (unsigned char *)"salt", 4) == 1);
        REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(ctx.getCtx(), salt_32.data(), salt_32.size()) == 1);
        REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(ctx.getCtx(), salt_64.data(), salt_64.size()) == 1);
        REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(ctx.getCtx(), salt_65.data(), salt_65.size()) == 0);
    }

    SECTION("HKBKDF set label")
    {
        AziHsmHkdf ctx = AziHsmHkdf(e);
        std::vector<unsigned char> label_16(16);
        REQUIRE(RAND_bytes(label_16.data(), label_16.size()) == 1);

        std::vector<unsigned char> label_17(17);
        REQUIRE(RAND_bytes(label_17.data(), label_17.size()) == 1);

        REQUIRE(EVP_PKEY_derive_init(ctx.getCtx()) == 1);
        REQUIRE(ctx.ctrl(-1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_CUSTOM_KBKDF, 0, nullptr) == 1);
        REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(ctx.getCtx(), (unsigned char *)"label", 5) == 1);
        REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(ctx.getCtx(), label_16.data(), label_16.size()) == 1);
        REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(ctx.getCtx(), label_17.data(), label_17.size()) == 0);
    }

    SECTION("HKDF with wrong Secret")
    {
        AziHsmHkdf ctx = AziHsmHkdf(e);

        REQUIRE(EVP_PKEY_derive_init(ctx.getCtx()) == 1);
        REQUIRE(EVP_PKEY_CTX_set1_hkdf_key(ctx.getCtx(), (unsigned char *)"wrongkey", 8) == 0);
    }

    SECTION("HKDF set info")
    {
        AziHsmHkdf ctx = AziHsmHkdf(e);
        std::vector<unsigned char> info(16);
        REQUIRE(RAND_bytes(info.data(), info.size()) == 1);
        std::vector<unsigned char> info_17(17);
        REQUIRE(RAND_bytes(info_17.data(), info_17.size()) == 1);

        // test append to the info
        REQUIRE(EVP_PKEY_derive_init(ctx.getCtx()) == 1);
        REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(ctx.getCtx(), (unsigned char *)"info", 5) == 1);
        REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(ctx.getCtx(), (unsigned char *)"more-info", 9) == 1);
        REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(ctx.getCtx(), (unsigned char *)"extra-info", 10) == 0);

        // test set info
        REQUIRE(EVP_PKEY_derive_init(ctx.getCtx()) == 1);
        REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(ctx.getCtx(), info.data(), info.size()) == 1);

        // test set info with wrong size
        REQUIRE(EVP_PKEY_derive_init(ctx.getCtx()) == 1);
        REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(ctx.getCtx(), info_17.data(), info_17.size()) == 0);
    }

    SECTION("HKDF with low-level ECDH (X9_62_prime256v1)")
    {
        int curve_name = NID_X9_62_prime256v1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512) == 1);
    }

    SECTION("HKDF with low-level ECDH (secp384r1)")
    {
        int curve_name = NID_secp384r1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512) == 1);
    }

    SECTION("HKDF with low-level ECDH (secp521r1)")
    {
        int curve_name = NID_secp521r1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512) == 1);
    }

    SECTION("KBKDF with low-level ECDH (X9_62_prime256v1)")
    {
        int curve_name = NID_X9_62_prime256v1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512, false, true) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512, false, true) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512, false, true) == 1);
    }

    SECTION("KBKDF with low-level ECDH (secp384r1)")
    {
        int curve_name = NID_secp384r1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512, false, true) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512, false, true) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512, false, true) == 1);
    }

    SECTION("KBKDF with low-level ECDH (secp521r1)")
    {
        int curve_name = NID_secp521r1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512, false, true) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512, false, true) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384, false, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512, false, true) == 1);
    }

    SECTION("HKDF with high-level ECDH (X9_62_prime256v1)")
    {
        int curve_name = NID_X9_62_prime256v1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512, true, false) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512, true, false) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512, true, false) == 1);
    }

    SECTION("HKDF with high-level ECDH (secp384r1)")
    {
        int curve_name = NID_secp384r1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512, true, false) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512, true, false) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512, true, false) == 1);
    }

    SECTION("HKDF with high-level ECDH (secp521r1)")
    {
        int curve_name = NID_secp521r1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512, true, false) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512, true, false) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384, true, false) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512, true, false) == 1);
    }

    SECTION("KBKDF with high-level ECDH (X9_62_prime256v1)")
    {
        int curve_name = NID_X9_62_prime256v1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512, true, true) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512, true, true) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512, true, true) == 1);
    }

    SECTION("KBKDF with high-level ECDH (secp384r1)")
    {
        int curve_name = NID_secp384r1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512, true, true) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512, true, true) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512, true, true) == 1);
    }

    SECTION("KBKDF with high-level ECDH (secp521r1)")
    {
        int curve_name = NID_secp521r1;

        // NID_aes_128_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha256, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha384, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_128_cbc, NID_sha512, true, true) == 1);

        // NID_aes_192_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha256, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha384, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_192_cbc, NID_sha512, true, true) == 1);

        // NID_aes_256_cbc with differnt digest
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha256, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha384, true, true) == 1);
        REQUIRE(testKeyDerivation(e, curve_name, NID_aes_256_cbc, NID_sha512, true, true) == 1);
    }
}
