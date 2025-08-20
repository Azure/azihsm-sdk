// Copyright (C) Microsoft Corporation. All rights reserved.

// Common Helper functions for tests

#include "AziHsmEc.hpp"
#include "AziHsmHash.hpp"
#include <memory>

AziHsmDigestKind get_azihsm_digest_kind(int md_type)
{
    switch (md_type)
    {
    case NID_sha1:
        return AZIHSM_DIGEST_SHA1;
    case NID_sha256:
        return AZIHSM_DIGEST_SHA256;
    case NID_sha384:
        return AZIHSM_DIGEST_SHA384;
    case NID_sha512:
        return AZIHSM_DIGEST_SHA512;
    default:
        return AziHsmDigestKind(0);
    }
}

AziHsmKeyUsage get_azihsm_key_usage(int ecdh)
{
    if (ecdh)
    {
        return AZIHSM_KEY_USAGE_DERIVE;
    }
    else
    {
        return AZIHSM_KEY_USAGE_SIGN_VERIFY;
    }
}

EC_KEY *ec_key_new_with_engine(ENGINE *e, int nid)
{
    EC_KEY *key = EC_KEY_new_method(e);
    if (key == nullptr)
    {
        return nullptr;
    }

    // create EC_GROUP with the given curve name and set it in the EC_KEY
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> ec_group(
        EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free);

    if (!ec_group)
    {
        EC_KEY_free(key);
        return nullptr;
    }

    if (EC_KEY_set_group(key, ec_group.get()) != 1)
    {
        EC_KEY_free(key);
        return nullptr;
    }
    return key;
}

// User must free the signature returned in der format after using with OPENSSL_free
unsigned char *to_der_encoded_sig(const unsigned char *data, size_t length, size_t *der_len)
{
    const unsigned char *p = data;
    size_t order_size = length / 2;
    BIGNUM *r = BN_bin2bn(p, order_size, NULL);
    BIGNUM *s = BN_bin2bn(p + order_size, order_size, NULL);
    if (r == NULL || s == NULL)
    {
        BN_free(r);
        BN_free(s);
        return nullptr;
    }
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (sig == NULL)
    {
        BN_free(r);
        BN_free(s);
        return nullptr;
    }
    if (ECDSA_SIG_set0(sig, r, s) != 1)
    {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return nullptr;
    }
    unsigned char *pout = NULL;
    int len = i2d_ECDSA_SIG(sig, &pout);
    if (len <= 0)
    {
        ECDSA_SIG_free(sig);
        return nullptr;
    }

    *der_len = len;
    ECDSA_SIG_free(sig);
    return pout;
}

// Compare two EC keys
// Returns 0 if keys are equal, 1 if keys are different, -1 if an error occurred
int ec_keys_compare(const EC_KEY *key1, const EC_KEY *key2)
{
    const EC_GROUP *group1 = EC_KEY_get0_group(key1);
    const EC_GROUP *group2 = EC_KEY_get0_group(key2);
    if (group1 == NULL || group2 == NULL)
    {
        return -1;
    }

    if (EC_GROUP_cmp(group1, group2, NULL) != 0)
    {
        return 1;
    }

    const EC_POINT *pub_key1 = EC_KEY_get0_public_key(key1);
    const EC_POINT *pub_key2 = EC_KEY_get0_public_key(key2);
    if (pub_key1 == NULL || pub_key2 == NULL)
    {
        return -1;
    }

    if (EC_POINT_cmp(group1, pub_key1, pub_key2, NULL) != 0)
    {
        return 1;
    }

    return 0;
}
