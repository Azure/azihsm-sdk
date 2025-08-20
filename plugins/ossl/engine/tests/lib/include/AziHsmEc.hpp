// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_EC_HPP
#define AZIHSM_EC_HPP

#include "AziHsmEngine.hpp"
#include <vector>

class AziHsmEcKeyMethod
{
public:
    AziHsmEcKeyMethod();
    AziHsmEcKeyMethod(ENGINE *e);

private:
    ENGINE *e;
};

class AziHsmEcKey
{
public:
    AziHsmEcKey(ENGINE *e = nullptr);
    AziHsmEcKey(EC_KEY *key);
    ~AziHsmEcKey();
    EC_KEY *getKey();
    unsigned int getSize();
    int keygen(int nid, bool ecdh);
    AziHsmEcKey copy();
    int sign(const std::vector<unsigned char> &dgst, std::vector<unsigned char> &sig);
    int verify(const std::vector<unsigned char> &dgst, const std::vector<unsigned char> &sig);
    ECDSA_SIG *ecdsa_sig_sign(const std::vector<unsigned char> &dgst);
    int ecdsa_sig_verify(const std::vector<unsigned char> &dgst, const ECDSA_SIG *sig);
    EC_KEY *unwrapTestKey(AziHsmEngine &azihsm_engine, int curve_name, bool ecdh, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1, int test_key_num = 0);
    const EC_POINT *getPublicKey();
    int getSharedSecretSize();
    void validate();
    int getNid();

private:
    EC_KEY *key;
    int nid;
    ENGINE *e;
};

// Common helper functions
AziHsmDigestKind get_azihsm_digest_kind(int md_type);
AziHsmKeyUsage get_azihsm_key_usage(int ecdh);

// User must free the signature returned in der format after using with OPENSSL_free
unsigned char *to_der_encoded_sig(const unsigned char *sig, size_t sig_len, size_t *der_len);

int ec_keys_compare(const EC_KEY *key1, const EC_KEY *key2);
EC_KEY *ec_key_new_with_engine(ENGINE *e, int nid);

#endif // AZIHSM_EC_HPP
