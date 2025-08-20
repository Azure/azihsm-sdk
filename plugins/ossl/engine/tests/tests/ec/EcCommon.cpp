// Copyright (C) Microsoft Corporation. All rights reserved.

// Common Helper functions for tests

#include "AziHsmTestEc.hpp"
#include "AziHsmTestHash.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include <stdexcept>
#include <catch2/catch_test_macros.hpp>

int curve_raw_signature_size(int curve_name)
{
    switch (curve_name)
    {
    case NID_X9_62_prime256v1:
        return 64;
    case NID_secp384r1:
        return 96;
    case NID_secp521r1:
        return 132;
    default:
        return 0;
    }
}

int curve_dgst_len(int curve_name)
{
    switch (curve_name)
    {
    case NID_X9_62_prime256v1:
        return 32;
    case NID_secp384r1:
        return 48;
    case NID_secp521r1:
        return 64;
    default:
        return 0;
    }
}

int next_allowed_curve(int curve_name)
{
    switch (curve_name)
    {
    case NID_X9_62_prime256v1:
        return curve_dgst_len(NID_secp384r1);
    case NID_secp384r1:
        return curve_dgst_len(NID_secp521r1);
    case NID_secp521r1:
        return 0;
    default:
        return 0;
    }
}

int compute_digest(int nid, std::vector<unsigned char> message, std::vector<unsigned char> &digest)
{
    AziHsmEvpMdCtx mdctx;

    const EVP_MD *md = EVP_get_digestbynid(nid);
    REQUIRE(md != nullptr);

    REQUIRE(EVP_DigestInit_ex(mdctx.getCtx(), md, NULL) == 1);
    REQUIRE(EVP_DigestUpdate(mdctx.getCtx(), (const char *)message.data(), message.size()) == 1);

    unsigned int digest_len;
    REQUIRE(EVP_DigestFinal_ex(mdctx.getCtx(), digest.data(), &digest_len) == 1);
    digest.resize(digest_len);
    return 1;
}

std::vector<unsigned char> get_test_ec_key(int key_num, int curve_name)
{
    switch (curve_name)
    {
    case NID_X9_62_prime256v1:
        return key_num == 0 ? std::vector<unsigned char>(ECC_PRIV_KEY_PRIME256V1)
                            : std::vector<unsigned char>(ECC_PRIV_KEY_PRIME256V1_2);
    case NID_secp384r1:
        return key_num == 0 ? std::vector<unsigned char>(ECC_PRIV_KEY_SECP384R1)
                            : std::vector<unsigned char>(ECC_PRIV_KEY_SECP384R1_2);
    case NID_secp521r1:
        return key_num == 0 ? std::vector<unsigned char>(ECC_PRIV_KEY_SECP521R1)
                            : std::vector<unsigned char>(ECC_PRIV_KEY_SECP521R1_2);
    default:
        throw std::runtime_error("Could not get test EC key");
    }
}

std::vector<unsigned char> wrap_test_ec_key(AziHsmEngine &azihsm_engine, int test_key_num, int curve_name, AziHsmDigestKind digest_kind)
{
    std::vector<unsigned char> target_key = get_test_ec_key(test_key_num, curve_name);
    if (target_key.size() <= 0)
    {
        throw std::runtime_error("Target key size <= 0");
    }

    std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
    if (unwrapping_key.size() <= 0)
    {
        throw std::runtime_error("Unwrapping key size <= 0");
    }

    std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, target_key, digest_kind);
    if (wrapped_blob.size() <= 0)
    {
        throw std::runtime_error("Wrapped blob size <= 0");
    }

    return wrapped_blob;
}

EC_KEY *unwrap_test_ec_key(
    AziHsmEngine &azihsm_engine,
    int curve_name,
    bool ecdh,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability,
    int test_key_num)
{
    std::vector<unsigned char> wrapped_blob = wrap_test_ec_key(azihsm_engine, test_key_num, curve_name, digest_kind);

    AziHsmKeyUsage key_usage = get_azihsm_key_usage(ecdh);
    if (key_usage == 0)
    {
        throw std::runtime_error("Key usage is invalid");
    }

    EC_KEY *ec_key = ec_key_new_with_engine(azihsm_engine.getEngine(), curve_name);
    if (ec_key == nullptr)
    {
        throw std::runtime_error("Could not create EC key");
    }

    if (azihsm_engine.unwrapEcKey(ec_key, key_usage, wrapped_blob, digest_kind) != 1)
    {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Could not unwrap EC key");
    }

    return ec_key;
}

// Verify the signature with OpenSSL native API.
void ec_verify_with_ossl(int curve_name, const EC_POINT *public_point, const std::vector<unsigned char> &signature, const std::vector<unsigned char> &digest)
{
    // Create EC key
    EC_KEY *public_ec_key = EC_KEY_new_by_curve_name(curve_name);
    REQUIRE(public_ec_key != nullptr);

    // Set public key group and public key
    REQUIRE(EC_KEY_set_public_key(public_ec_key, public_point) == 1);
    REQUIRE(EC_KEY_check_key(public_ec_key) == 1);

    EVP_PKEY *public_pkey = EVP_PKEY_new();
    REQUIRE(EVP_PKEY_set1_EC_KEY(public_pkey, public_ec_key) == 1);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_pkey, nullptr);
    REQUIRE(ctx != nullptr);

    size_t sig_der_len;
    unsigned char *sig_der = to_der_encoded_sig(signature.data(), signature.size(), &sig_der_len);
    REQUIRE(sig_der != nullptr);
    REQUIRE(sig_der_len != 0);

    // Verify with EC_KEY API.
    REQUIRE(ECDSA_verify(0, digest.data(), digest.size(), sig_der, sig_der_len, public_ec_key) == 1);

    // Verify with EVP_PKEY API.
    REQUIRE(EVP_PKEY_verify_init(ctx) == 1);
    REQUIRE(EVP_PKEY_verify(ctx, sig_der, sig_der_len, digest.data(), digest.size()) == 1);

    // Free key
    EVP_PKEY_free(public_pkey);
    EC_KEY_free(public_ec_key);
    OPENSSL_free(sig_der);
}