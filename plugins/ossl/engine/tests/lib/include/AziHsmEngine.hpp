// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_ENGINE_HPP
#define AZIHSM_ENGINE_HPP

#define OPENSSL_USE_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED

#include <vector>
#include <openssl/engine.h>
#include <string>
#include "../../../api-interface/azihsm_engine.h"

enum class KeyType
{
    KEYGEN,
    UNWRAP
};

class AziHsmEngine
{
public:
    // Constructor/destructor
    AziHsmEngine(const std::string &path, const std::string &engine_id = "libazihsmengine");
    ~AziHsmEngine();

    // Member functions
    ENGINE *getEngine();

    // Key wrap helper functions
    std::vector<unsigned char> getBuiltinUnwrappingKey();

    std::vector<unsigned char> wrapTargetKey(
        const std::vector<unsigned char> &wrapping_key,
        const std::vector<unsigned char> &target_key,
        const AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1);

    // Key unwrap helper functions
    int unwrapEcKey(
        EC_KEY *ec_key,
        AziHsmKeyUsage key_usage,
        std::vector<unsigned char> wrapped_key,
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
        const char *name = nullptr,
        AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION);
    int unwrapPKeyEc(
        EVP_PKEY_CTX *ctx,
        int curve_name,
        AziHsmKeyUsage key_usage,
        std::vector<unsigned char> wrapped_key,
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
        const char *name = nullptr,
        AziHsmKeyAvailability keyAvailability = AZIHSM_AVAILABILITY_SESSION);
    int unwrapPKeyRsa(
        EVP_PKEY_CTX *ctx,
        AziHsmKeyUsage key_usage,
        std::vector<unsigned char> wrapped_key,
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
        const char *name = nullptr,
        AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION);
    int unwrapRsa(
        RSA *rsa, AziHsmKeyUsage key_usage,
        std::vector<unsigned char> wrapped_key,
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
        const char *name = nullptr,
        AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION);
    int unwrapAes(
        EVP_CIPHER_CTX *ctx,
        int nid,
        std::vector<unsigned char> wrapped_key,
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
        const char *name = nullptr,
        AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION);
    int unwrapAesXts(
        EVP_CIPHER_CTX *ctx,
        std::vector<unsigned char> wrapped_key1,
        std::vector<unsigned char> wrapped_key2,
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
        const char *name = nullptr,
        AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION);

    // Attestation helper functions
    int attestBuiltinUnwrapKey(std::vector<unsigned char> report_data, std::vector<unsigned char> &claim);

    int attestEcKey(EC_KEY *ec_key, std::vector<unsigned char> report_data, std::vector<unsigned char> &claim);

    int attestRsa(RSA *rsa, std::vector<unsigned char> report_data, std::vector<unsigned char> &claim);

    int attestEcPKey(EVP_PKEY *pkey, std::vector<unsigned char> report_data, std::vector<unsigned char> &claim);

    int attestRsaPKey(EVP_PKEY *pkey, std::vector<unsigned char> report_data, std::vector<unsigned char> &claim);

    std::vector<unsigned char> getCollateral();

private:
    ENGINE *engine;
};

#endif // AZIHSM_ENGINE_HPP
