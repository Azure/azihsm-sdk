// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef OPENSSL_DIGEST_SIGN_H
#define OPENSSL_DIGEST_SIGN_H

#include <openssl/evp.h>
#include <vector>
#include <stdlib.h>
#include "AziHsmPKeys.hpp"
#include "AziHsmHash.hpp"

class AziHsmDigestSignVerify
{
public:
    AziHsmDigestSignVerify() : e(nullptr), pkey(nullptr), hash(AziHsmShaHashType::SHA1) {};
    AziHsmDigestSignVerify(ENGINE *e, EVP_PKEY *pkey, AziHsmShaHashType hash_type);

    int sign(std::vector<unsigned char> &sig, const std::vector<unsigned char> &data);
    int verify(const std::vector<unsigned char> &sig, const std::vector<unsigned char> &data);

private:
    ENGINE *e;
    EVP_PKEY *pkey;
    AziHsmShaHash hash;
};

#endif // OPENSSL_DIGEST_SIGN_H
