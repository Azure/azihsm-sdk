// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmEngine.hpp"
#include "AziHsmEc.hpp"
#include "AziHsmPKeys.hpp"
#include "AziHsmScopeGuard.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <filesystem>
#include <string>
#include <cstring>
#include <memory>
#include <stdexcept>

AziHsmEngine::AziHsmEngine(const std::string &path, const std::string &engine_id)
{
    // Load and Get structural reference
    ENGINE_load_dynamic();
    engine = ENGINE_by_id("dynamic");
    if (engine == nullptr)
    {
        throw std::runtime_error("Loading Dynamic Engine failed");
    }

    int result = ENGINE_ctrl_cmd_string(engine, "SO_PATH", path.c_str(), 0);

    if (result != 1)
    {
        throw std::runtime_error("Setting AZIHSM Engine SO_PATH failed");
    }

    result = ENGINE_ctrl_cmd_string(engine, "ID", engine_id.c_str(), 0);
    if (result != 1)
    {
        throw std::runtime_error("Setting AZIHSM Engine ID failed");
    }

    result = ENGINE_ctrl_cmd_string(engine, "LOAD", nullptr, 0);
    if (result != 1)
    {
        throw std::runtime_error("Loading AZIHSM Engine failed");
    }

    // Get functional and structural reference
    result = ENGINE_init(engine);
    if (result != 1)
    {
        throw std::runtime_error("Initializing AZIHSM Engine failed");
    }
}

AziHsmEngine::~AziHsmEngine()
{
    // Release functional and structural reference
    ENGINE_finish(engine);
    // Release structural reference
    ENGINE_free(engine);
}

ENGINE *AziHsmEngine::getEngine()
{
    return engine;
}

int AziHsmEngine::unwrapEcKey(
    EC_KEY *ec_key,
    AziHsmKeyUsage key_usage,
    std::vector<unsigned char> wrapped_key,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability)
{
    return azihsm_unwrap_ecc(engine, ec_key, digest_kind, key_usage, wrapped_key.data(), wrapped_key.size(), name, availability);
}

int AziHsmEngine::unwrapPKeyEc(
    EVP_PKEY_CTX *ctx,
    int curve_name,
    AziHsmKeyUsage key_usage,
    std::vector<unsigned char> wrapped_key,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability)
{
    return azihsm_unwrap_evp_pkey_ecc(engine, ctx, curve_name, digest_kind, key_usage, wrapped_key.data(), wrapped_key.size(), name, availability);
}

int AziHsmEngine::unwrapPKeyRsa(
    EVP_PKEY_CTX *ctx,
    AziHsmKeyUsage key_usage,
    std::vector<unsigned char> wrapped_key,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability)
{
    return azihsm_unwrap_evp_pkey_rsa(engine, ctx, digest_kind, key_usage, wrapped_key.data(), wrapped_key.size(), name, availability);
}

int AziHsmEngine::unwrapRsa(
    RSA *rsa,
    AziHsmKeyUsage key_usage,
    std::vector<unsigned char> wrapped_key,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability)
{
    return azihsm_unwrap_rsa(engine, rsa, digest_kind, key_usage, wrapped_key.data(), wrapped_key.size(), name, availability);
}

int AziHsmEngine::unwrapAes(
    EVP_CIPHER_CTX *ctx,
    int nid,
    std::vector<unsigned char> wrapped_key,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability)
{
    return azihsm_unwrap_aes(engine, ctx, nid, digest_kind, wrapped_key.data(), wrapped_key.size(), name, availability);
}

int AziHsmEngine::unwrapAesXts(
    EVP_CIPHER_CTX *ctx,
    std::vector<unsigned char> wrapped_key1,
    std::vector<unsigned char> wrapped_key2,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability)
{
    return azihsm_unwrap_aes_xts(
        engine,
        ctx,
        digest_kind,
        wrapped_key1.data(),
        wrapped_key1.size(),
        wrapped_key2.data(),
        wrapped_key2.size(),
        name,
        availability);
}

int AziHsmEngine::attestBuiltinUnwrapKey(std::vector<unsigned char> report_data, std::vector<unsigned char> &claim)
{
    size_t claim_len = 0;

    if (azihsm_attest_builtin_unwrap_key(engine, report_data.data(), report_data.size(), nullptr, &claim_len) != 1)
    {
        return 0;
    }

    if (claim_len == 0)
    {
        return 0;
    }

    claim.resize(claim_len);
    return azihsm_attest_builtin_unwrap_key(engine, report_data.data(), report_data.size(), claim.data(), &claim_len);
}

int AziHsmEngine::attestEcKey(EC_KEY *ec_key, std::vector<unsigned char> report_data, std::vector<unsigned char> &claim)
{
    size_t claim_len = 0;

    if (azihsm_attest_ecc(engine, ec_key, report_data.data(), report_data.size(), nullptr, &claim_len) != 1)
    {
        return 0;
    }

    if (claim_len == 0)
    {
        return 0;
    }

    claim.resize(claim_len);
    return azihsm_attest_ecc(engine, ec_key, report_data.data(), report_data.size(), claim.data(), &claim_len);
}

int AziHsmEngine::attestRsa(RSA *rsa, std::vector<unsigned char> report_data, std::vector<unsigned char> &claim)
{
    size_t claim_len = 0;

    if (azihsm_attest_rsa(engine, rsa, report_data.data(), report_data.size(), nullptr, &claim_len) != 1)
    {
        return 0;
    }

    if (claim_len == 0)
    {
        return 0;
    }

    claim.resize(claim_len);
    return azihsm_attest_rsa(engine, rsa, report_data.data(), report_data.size(), claim.data(), &claim_len);
}

int AziHsmEngine::attestEcPKey(EVP_PKEY *pkey, std::vector<unsigned char> report_data, std::vector<unsigned char> &claim)
{
    size_t claim_len = 0;

    if (azihsm_attest_evp_pkey_ecc(engine, pkey, report_data.data(), report_data.size(), nullptr, &claim_len) != 1)
    {
        return 0;
    }

    if (claim_len == 0)
    {
        return 0;
    }

    claim.resize(claim_len);
    return azihsm_attest_evp_pkey_ecc(engine, pkey, report_data.data(), report_data.size(), claim.data(), &claim_len);
}

int AziHsmEngine::attestRsaPKey(EVP_PKEY *pkey, std::vector<unsigned char> report_data, std::vector<unsigned char> &claim)
{
    size_t claim_len = 0;

    if (azihsm_attest_evp_pkey_rsa(engine, pkey, report_data.data(), report_data.size(), nullptr, &claim_len) != 1)
    {
        return 0;
    }

    if (claim_len = 0)
    {
        return 0;
    }

    claim.resize(claim_len);
    return azihsm_attest_evp_pkey_rsa(engine, pkey, report_data.data(), report_data.size(), claim.data(), &claim_len);
}

std::vector<unsigned char> AziHsmEngine::getCollateral()
{
    std::vector<unsigned char> collateral;
    size_t collateral_len = 0;
    if (azihsm_get_collateral(engine, nullptr, &collateral_len) != 1 || collateral_len == 0)
    {
        throw std::runtime_error("Could not get collateral size");
    }

    collateral.resize(collateral_len);
    if (azihsm_get_collateral(engine, collateral.data(), &collateral_len) != 1)
    {
        throw std::runtime_error("Could not get collateral");
    }
    return collateral;
}

std::vector<unsigned char> AziHsmEngine::getBuiltinUnwrappingKey()
{
    std::vector<unsigned char> unwrapping_key;
    AziHsmUnwrappingKey key;
    std::memset(&key, 0, sizeof(AziHsmUnwrappingKey));
    if (azihsm_get_builtin_unwrap_key(engine, &key) != 1 || key.key_len == 0)
    {
        throw std::runtime_error("Could not get builtin wrapping key size");
    }

    unwrapping_key.resize(key.key_len);
    key.key = unwrapping_key.data();
    if (azihsm_get_builtin_unwrap_key(engine, &key) != 1)
    {
        throw std::runtime_error("Could not get builtin wrapping key");
    }
    return unwrapping_key;
}

std::vector<unsigned char> AziHsmEngine::wrapTargetKey(
    const std::vector<unsigned char> &wrapping_key,
    const std::vector<unsigned char> &target_key,
    const AziHsmDigestKind digest_kind)
{
    // Generate Aes 256 key using rand_bytes
    std::vector<unsigned char> aes_key(32);
    if (RAND_bytes(aes_key.data(), aes_key.size()) != 1)
    {
        throw std::runtime_error("Could not get random bytes for AES key");
    }

    // Create pub key context; for unclear OpenSSL reasons, this only works with RSA methods.
    const unsigned char *kptr = wrapping_key.data();
    RSA *pub_key = d2i_RSA_PUBKEY(nullptr, &kptr, wrapping_key.size());
    if (pub_key == nullptr)
    {
        throw std::runtime_error("Could not get public key");
    }

    // Create EVP_PKEY object from RSA key
    EVP_PKEY *raw_pkey = EVP_PKEY_new();
    if (raw_pkey == nullptr)
    {
        // Unassigned yet, so free
        RSA_free(pub_key);
        throw std::runtime_error("Could not get raw pkey");
    }
    AziHsmPKey pub_pkey(raw_pkey);
    if (EVP_PKEY_assign_RSA(pub_pkey.getPKey(), pub_key) != 1) // If successful, pub_key will be freed when PKEY is
    {
        // Could not assign, so free it
        RSA_free(pub_key);
        throw std::runtime_error("Could not assign RSA public key to pkey");
    }

    // Create encryption context
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> encrypt_ctx(
        EVP_PKEY_CTX_new(pub_pkey.getPKey(), nullptr),
        [](EVP_PKEY_CTX *ctx)
        { if (ctx) EVP_PKEY_CTX_free(ctx); });
    if (encrypt_ctx.get() == nullptr)
    {
        throw std::runtime_error("Could not create encryption context");
    }

    // Choose the digest (hash) algorithm based on the digest_kind
    const EVP_MD *md = nullptr;
    switch (digest_kind)
    {
    case AziHsmDigestKind::AZIHSM_DIGEST_SHA1:
        md = EVP_sha1();
        break;
    case AziHsmDigestKind::AZIHSM_DIGEST_SHA256:
        md = EVP_sha256();
        break;
    case AziHsmDigestKind::AZIHSM_DIGEST_SHA384:
        md = EVP_sha384();
        break;
    case AziHsmDigestKind::AZIHSM_DIGEST_SHA512:
        md = EVP_sha512();
        break;
    }
    if (md == nullptr)
    {
        throw std::runtime_error("Could not get EVP hash");
    }

    // Initialize encryption with RSA and OAEP padding
    if (EVP_PKEY_encrypt_init(encrypt_ctx.get()) != 1)
    {
        throw std::runtime_error("Could not init encrypt ctx");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(encrypt_ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1)
    {
        throw std::runtime_error("Could not set RSA padding on encrypt ctx");
    }

    // Set the message digest for OAEP padding
    if (EVP_PKEY_CTX_set_rsa_oaep_md(encrypt_ctx.get(), md) != 1)
    {
        throw std::runtime_error("Could not set message digest on encrypt ctx");
    }

    // Determine the size of the encrypted output
    size_t encryptlen = 0;
    if (EVP_PKEY_encrypt(encrypt_ctx.get(), nullptr, &encryptlen, aes_key.data(), aes_key.size()) != 1 || encryptlen == 0)
    {
        throw std::runtime_error("Could not get encrypted size of AES key");
    }

    // Allocate buffer for the RSA-encrypted AES key

    const EVP_CIPHER *cipher = EVP_aes_256_wrap_pad();
#ifdef OPENSSL_3
    int block_size = EVP_CIPHER_get_block_size(cipher);
#else
    int block_size = EVP_CIPHER_block_size(cipher);
#endif
    if (block_size <= 0)
    {
        throw std::runtime_error("Could not get cipher block size");
    }
    size_t padding = 8 - target_key.size() % 8;
    std::vector<unsigned char> buffer(RSA_size(pub_key) + target_key.size() + padding + block_size * 2);
    if (EVP_PKEY_encrypt(encrypt_ctx.get(), buffer.data(), &encryptlen, aes_key.data(), aes_key.size()) != 1 || encryptlen == 0)
    {
        throw std::runtime_error("Could not encrypt AES key");
    }

    /// Now wrap the target key using AES
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher_ctx(
        EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX *ctx)
        { if (ctx) EVP_CIPHER_CTX_free(ctx); });
    if (cipher_ctx.get() == nullptr)
    {
        throw std::runtime_error("Could not create cipher ctx");
    }

    EVP_CIPHER_CTX_set_flags(cipher_ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_EncryptInit_ex(cipher_ctx.get(), cipher, nullptr, aes_key.data(), nullptr) <= 0)
    {
        throw std::runtime_error("Could not initialize cipher ctx encryption");
    }

    // Encrypt the target key
    int count = 0, rest = 0;
    unsigned char *bufptr = buffer.data() + (size_t)encryptlen;
    if (EVP_CipherUpdate(cipher_ctx.get(), bufptr, &count, target_key.data(), target_key.size()) <= 0)
    {
        throw std::runtime_error("Could not update cipher ctx with key data");
    }

    if (EVP_CipherFinal_ex(cipher_ctx.get(), bufptr, &rest) <= 0)
    {
        throw std::runtime_error("Could not finalize cipher ctx");
    }

    if (encryptlen + count <= 0)
    {
        throw std::runtime_error("Encryption length <= 0");
    }

    // Resize buffer
    buffer.resize(encryptlen + count + rest);
    return buffer;
}
