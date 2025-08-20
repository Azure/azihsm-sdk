// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_PKEY_HKDF_HPP
#define AZIHSM_PKEY_HDKF_HPP

#include "AziHsmPKeys.hpp"
#include "AziHsmCiphers.hpp"
#include <vector>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

class AziHsmHkdf : public AziHsmPKeyCtx
{
public:
    AziHsmHkdf(ENGINE *e) : AziHsmPKeyCtx(EVP_PKEY_HKDF, e) {}
    AziHsmHkdf(ENGINE *e, std::vector<unsigned char> secret, int key_type, int md, bool hkdf);

    int getKeyType() { return this->key_type; };
    int getAesKeyLen() { return this->aes_key_len; };
    int getPrkLen() { return this->prk_len; };
    int getMd() { return this->md; };

    int derive(std::vector<unsigned char> &salt, std::vector<unsigned char> &info, std::vector<unsigned char> &aes_key);
    int expand(std::vector<unsigned char> &salt, std::vector<unsigned char> &info, std::vector<unsigned char> &prk, std::vector<unsigned char> &aes_key);

    // Helper function to determine secret size based on curve_name
    static int getSecretSize(int curve_name);

private:
    std::vector<unsigned char> secret;
    bool hkdf;
    int key_type;
    int aes_key_len;
    int prk_len;
    int md;
};

#endif // AZIHSM_PKEY_HKDF_HPP