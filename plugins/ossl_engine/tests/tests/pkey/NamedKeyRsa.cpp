// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmPKeys.hpp"
#include "AziHsmHash.hpp"
#include <catch2/catch_test_macros.hpp>
#include <vector>

RSA *rsa_extract_ossl_pub_key(AziHsmPKeyCtx &priv_key_ctx)
{
    RSA *hsm_rsa = EVP_PKEY_get1_RSA(priv_key_ctx.getPKey());
    REQUIRE(hsm_rsa != nullptr);

    const BIGNUM *n = NULL, *e = NULL;
    RSA_get0_key(hsm_rsa, &n, &e, NULL);
    RSA_free(hsm_rsa);

    BIGNUM *n_dup = BN_dup(n);
    BIGNUM *e_dup = BN_dup(e);
    REQUIRE(n_dup != nullptr);
    REQUIRE(e_dup != nullptr);

    RSA *rsa_pub = RSA_new();
    REQUIRE(rsa_pub != nullptr);

    REQUIRE(RSA_set0_key(rsa_pub, n_dup, e_dup, NULL) == 1);

    return rsa_pub;
}

EVP_PKEY *evp_pkey_rsa_extract_ossl_pub_key(AziHsmPKeyCtx &priv_key_ctx)
{
    RSA *rsa_pub = rsa_extract_ossl_pub_key(priv_key_ctx);

    EVP_PKEY *pub_key = EVP_PKEY_new();
    REQUIRE(pub_key != nullptr);
    REQUIRE(EVP_PKEY_assign_RSA(pub_key, rsa_pub) == 1);

    return pub_key;
}

int evp_pkey_encrypt_with_ossl_pubkey(EVP_PKEY *pkey_pub, std::vector<unsigned char> &encrypted_data, const std::vector<unsigned char> &plain_data, AziHsmShaHashType md_type = AziHsmShaHashType::SHA256)
{
    EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(pkey_pub, nullptr);
    REQUIRE(encrypt_ctx != nullptr);

    size_t outlen;
    REQUIRE(EVP_PKEY_encrypt_init(encrypt_ctx) == 1);
    REQUIRE(EVP_PKEY_CTX_set_rsa_padding(encrypt_ctx, RSA_PKCS1_OAEP_PADDING) == 1);

    if (md_type == AziHsmShaHashType::SHA1)
        REQUIRE(EVP_PKEY_CTX_set_rsa_oaep_md(encrypt_ctx, EVP_sha1()) == 1);
    else if (md_type == AziHsmShaHashType::SHA256)
        REQUIRE(EVP_PKEY_CTX_set_rsa_oaep_md(encrypt_ctx, EVP_sha256()) == 1);
    else if (md_type == AziHsmShaHashType::SHA384)
        REQUIRE(EVP_PKEY_CTX_set_rsa_oaep_md(encrypt_ctx, EVP_sha384()) == 1);
    else if (md_type == AziHsmShaHashType::SHA512)
        REQUIRE(EVP_PKEY_CTX_set_rsa_oaep_md(encrypt_ctx, EVP_sha512()) == 1);

    REQUIRE(EVP_PKEY_encrypt(encrypt_ctx, nullptr, &outlen, plain_data.data(), plain_data.size()) == 1);

    encrypted_data.resize(outlen);
    REQUIRE(EVP_PKEY_encrypt(encrypt_ctx, encrypted_data.data(), &outlen, plain_data.data(), plain_data.size()) == 1);

    EVP_PKEY_CTX_free(encrypt_ctx);
    return outlen;
}

int rsa_verify_with_ossl_pubkey(RSA *rsa_pub, const std::vector<unsigned char> &signature, const std::vector<unsigned char> &digest)
{
    int rsa_verify_result = RSA_verify(NID_sha1, digest.data(), digest.size(), signature.data(), signature.size(), rsa_pub);
    return rsa_verify_result;
}

int evp_pkey_verify_with_ossl_pubkey(EVP_PKEY *pkey_pub, const std::vector<unsigned char> &signature, const std::vector<unsigned char> &digest, AziHsmShaHashType md_type = AziHsmShaHashType::SHA256, int padding = RSA_PKCS1_PADDING)
{
    AziHsmShaHash md(md_type);

    EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new(pkey_pub, nullptr);
    REQUIRE(verify_ctx != nullptr);
    REQUIRE(EVP_PKEY_verify_init(verify_ctx) == 1);

    REQUIRE(EVP_PKEY_CTX_set_signature_md(verify_ctx, md.getType()) == 1);

    REQUIRE(EVP_PKEY_CTX_set_rsa_padding(verify_ctx, padding) == 1);

    REQUIRE(EVP_PKEY_verify(verify_ctx, signature.data(), signature.size(), digest.data(), digest.size()) == 1);

    EVP_PKEY_CTX_free(verify_ctx);
    return 1;
}

static AziHsmPKeyCtx unwrap_and_load_named_key(AziHsmEngine &azihsm_engine, const char *name, const std::vector<unsigned char> &target_key, AziHsmKeyUsage key_usage)
{
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    // Unwrap named key
    {
        std::vector<unsigned char> wrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(wrapping_key, target_key);
        REQUIRE(wrapped_blob.size() > 0);

        AziHsmPKey pkey(EVP_PKEY_RSA);
        AziHsmPKeyCtx priv_key_ctx(pkey.getPKey(), e);
        REQUIRE(azihsm_engine.unwrapPKeyRsa(
                    priv_key_ctx.getCtx(),
                    key_usage,
                    wrapped_blob,
                    AZIHSM_DIGEST_SHA1,
                    name,
                    AZIHSM_AVAILABILITY_APP) == 1);
    }

    // Retrieve key
    AziHsmPKey pkey(e, name);
    REQUIRE(pkey.getPKey() != nullptr);
    AziHsmPKeyCtx priv_key_ctx(pkey.getPKey(), e);
    REQUIRE(priv_key_ctx.getCtx() != nullptr);

    return priv_key_ctx;
}

static void
test_encrypt_decrypt(AziHsmEngine &azihsm_engine, const char *name, const std::vector<unsigned char> &target_key, size_t data_size)
{
    // 1. Unwrap and load named HSM key
    AziHsmPKeyCtx priv_key_ctx = unwrap_and_load_named_key(azihsm_engine, name, target_key, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);

    std::vector<unsigned char> plain_data(data_size);
    REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

    std::vector<unsigned char> encrypted_data;
    std::vector<unsigned char> decrypted_data(data_size);

    // 2.  Encrypt and decrypt with HSM key
    int hsm_encrypted_len = priv_key_ctx.encrypt(encrypted_data, plain_data);
    REQUIRE(hsm_encrypted_len > 0);

    int hsm_decrypted_len = priv_key_ctx.decrypt(decrypted_data, encrypted_data);
    REQUIRE(hsm_decrypted_len > 0);

    REQUIRE(plain_data == decrypted_data);

    // 3. Encrypt with OpenSSL public key and decrypt with HSM private key

    EVP_PKEY *pkey_pub = evp_pkey_rsa_extract_ossl_pub_key(priv_key_ctx);
    REQUIRE(pkey_pub != nullptr);

    std::vector<unsigned char> encrypted_data_ossl;

    // 3.1 Encrypt with OpenSSL public key
    int ossl_encrypted_len = evp_pkey_encrypt_with_ossl_pubkey(pkey_pub, encrypted_data_ossl, plain_data);

    REQUIRE(ossl_encrypted_len > 0);
    REQUIRE(hsm_encrypted_len == ossl_encrypted_len);
    decrypted_data.clear();

    // 3.2 Decrypt with HSM private key
    REQUIRE(priv_key_ctx.decrypt(decrypted_data, encrypted_data_ossl) > 0);
    REQUIRE(plain_data == decrypted_data);

    EVP_PKEY_free(pkey_pub);

    // 4.  Delete named key then try retrieving
    REQUIRE(azihsm_delete_key(azihsm_engine.getEngine(), name) == 1);
    EVP_PKEY *key = ENGINE_load_private_key(azihsm_engine.getEngine(), name, nullptr, nullptr);
    REQUIRE(key == nullptr);
}

static void test_sign_verify(AziHsmEngine &azihsm_engine, const char *name, const std::vector<unsigned char> &target_key, AziHsmShaHashType md_type)
{
    AziHsmShaHash md(md_type);
    // 1. Unwrap and load named HSM key
    AziHsmPKeyCtx priv_key_ctx = unwrap_and_load_named_key(azihsm_engine, name, target_key, AZIHSM_KEY_USAGE_SIGN_VERIFY);

    // 2. Create fake digest to sign
    std::vector<unsigned char> digest(md.getSize());
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    // 3. Sign and verify with HSM key
    std::vector<unsigned char> signature;
    REQUIRE(priv_key_ctx.sign(signature, digest) == 1);
    REQUIRE(priv_key_ctx.verify(signature, digest) == 1);

    // 4. Extract public key from HSM private key
    EVP_PKEY *evp_pubkey = evp_pkey_rsa_extract_ossl_pub_key(priv_key_ctx);
    REQUIRE(evp_pubkey != nullptr);

    // 5. Verify with OpenSSL using public key
    REQUIRE(evp_pkey_verify_with_ossl_pubkey(evp_pubkey, signature, digest) == 1);

    // 5. Delete named key then try retrieving
    REQUIRE(azihsm_delete_key(azihsm_engine.getEngine(), name) == 1);
    EVP_PKEY *key = ENGINE_load_private_key(azihsm_engine.getEngine(), name, nullptr, nullptr);
    REQUIRE(key == nullptr);
}

#ifdef AZIHSM_NAMED_KEYS
TEST_CASE("AZIHSM RSA named keys", "[AziHsmEngineRSANamedKeys]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    const char *name = "42";

    SECTION("Creating, deleting, and retrieving named key")
    {
        // Create and drop keys
        {
            std::vector<unsigned char> wrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
            std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(wrapping_key, RSA_PRIV_KEY_2048);
            REQUIRE(wrapped_blob.size() > 0);

            AziHsmPKey pkey(EVP_PKEY_RSA);
            AziHsmPKeyCtx priv_key_ctx(pkey.getPKey(), e);
            REQUIRE(azihsm_engine.unwrapPKeyRsa(
                        priv_key_ctx.getCtx(),
                        AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT,
                        wrapped_blob,
                        AZIHSM_DIGEST_SHA1,
                        name,
                        AZIHSM_AVAILABILITY_APP) == 1);
        }

        // Test key retrieval
        {
            AziHsmPKey pkey(e, name);
            REQUIRE(pkey.getPKey() != nullptr);
        }

        // Delete named key then try retrieving
        REQUIRE(azihsm_delete_key(e, name) == 1);
        EVP_PKEY *key = ENGINE_load_private_key(e, name, nullptr, nullptr);
        REQUIRE(key == nullptr);
    }

    SECTION("Encrypting/decrypting with a HSM named key")
    {
        // TODO: Enhance test coverage
        test_encrypt_decrypt(azihsm_engine, name, RSA_PRIV_KEY_2048, 32);
        test_encrypt_decrypt(azihsm_engine, name, RSA_PRIV_KEY_3072, 32);
        test_encrypt_decrypt(azihsm_engine, name, RSA_PRIV_KEY_4096, 32);
    }

    SECTION("Signing/verifying with a named key")
    {
        // TODO: Enhance test coverage (test different Hash Algorithm)
        test_sign_verify(azihsm_engine, name, RSA_PRIV_KEY_2048, AziHsmShaHashType::SHA256);
        test_sign_verify(azihsm_engine, name, RSA_PRIV_KEY_3072, AziHsmShaHashType::SHA256);
        test_sign_verify(azihsm_engine, name, RSA_PRIV_KEY_4096, AziHsmShaHashType::SHA256);
    }
}
#endif
