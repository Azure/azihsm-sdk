// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_HASH_H
#define AZIHSM_HASH_H

#include <openssl/evp.h>
#include <vector>
#include <stdlib.h>

enum class AziHsmShaHashType
{
    SHA1,
    SHA256,
    SHA384,
    SHA512,
};

class AziHsmEvpMdCtx
{
public:
    AziHsmEvpMdCtx(EVP_PKEY_CTX *pctx = nullptr);
    ~AziHsmEvpMdCtx();
    EVP_MD_CTX *getCtx();
    int setEvpPkeyCtx(EVP_PKEY_CTX *pctx);

private:
    EVP_MD_CTX *ctx;
    EVP_PKEY_CTX *pctx;
};

class AziHsmShaHash
{
public:
    AziHsmShaHash(AziHsmShaHashType);
    AziHsmShaHash(const EVP_MD *type) : ctx(), type((EVP_MD *)type) {};
    std::vector<unsigned char> hashData(std::vector<unsigned char> &);
    int getNid();
    int getSize();
    EVP_MD *getType();
    EVP_MD_CTX *getCtx();
    AziHsmShaHashType getHashType();

private:
    EVP_MD *type;
    AziHsmEvpMdCtx ctx;
};

#endif // AZIHSM_HASH_H
