// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmEngine.hpp"
#include "AziHsmHash.hpp"
#include <stdexcept>
#include <vector>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

AziHsmEvpMdCtx::AziHsmEvpMdCtx(EVP_PKEY_CTX *pctx)
    : pctx(pctx)
{
    this->ctx = EVP_MD_CTX_create();
    if (this->ctx == nullptr)
    {
        throw std::runtime_error("Could not create EVP_MD_CTX");
    }

    if (pctx != nullptr)
    {
        EVP_MD_CTX_set_pkey_ctx(this->ctx, pctx);
    }
}

AziHsmEvpMdCtx::~AziHsmEvpMdCtx()
{
    if (this->pctx != nullptr)
    {
        EVP_PKEY_CTX_free(this->pctx);
    }
    EVP_MD_CTX_destroy(this->ctx);
}

EVP_MD_CTX *AziHsmEvpMdCtx::getCtx()
{
    return this->ctx;
}

AziHsmShaHash::AziHsmShaHash(AziHsmShaHashType type)
{
    switch (type)
    {
    case AziHsmShaHashType::SHA512:
    {
        this->type = (EVP_MD *)EVP_sha512();
        break;
    }
    case AziHsmShaHashType::SHA384:
    {
        this->type = (EVP_MD *)EVP_sha384();
        break;
    }
    case AziHsmShaHashType::SHA256:
    {
        this->type = (EVP_MD *)EVP_sha256();
        break;
    }
    case AziHsmShaHashType::SHA1:
    {
        this->type = (EVP_MD *)EVP_sha1();
        break;
    }
    default:
    {
        throw std::runtime_error("Could not detect SHA type");
    }
    }
}

int AziHsmShaHash::getSize()
{
    return EVP_MD_size(this->type);
}

int AziHsmShaHash::getNid()
{
    return EVP_MD_type(this->type);
}

EVP_MD *AziHsmShaHash::getType()
{
    return this->type;
}

EVP_MD_CTX *AziHsmShaHash::getCtx()
{
    return this->ctx.getCtx();
}

AziHsmShaHashType AziHsmShaHash::getHashType()
{
    int nid = this->getNid();
    switch (nid)
    {
    case NID_sha1:
        return AziHsmShaHashType::SHA1;
    case NID_sha256:
        return AziHsmShaHashType::SHA256;
    case NID_sha384:
        return AziHsmShaHashType::SHA384;
    case NID_sha512:
        return AziHsmShaHashType::SHA512;
    default:
        throw std::runtime_error("Invalid NID passed");
    }
}

std::vector<unsigned char> AziHsmShaHash::hashData(std::vector<unsigned char> &data)
{
    if (!EVP_DigestInit_ex(this->getCtx(), this->type, NULL))
    {
        throw std::runtime_error("Could not initialize EVP digest");
    }

    if (!EVP_DigestUpdate(this->getCtx(), data.data(), data.size()))
    {
        throw std::runtime_error("Could not update digest");
    }

    size_t len = EVP_MD_CTX_size(this->getCtx());
    std::vector<unsigned char> hash(len);

    if (!EVP_DigestFinal_ex(this->getCtx(), hash.data(), (unsigned int *)&len))
    {
        throw std::runtime_error("Could not finalize digest");
    }

    return hash;
}
