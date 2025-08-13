// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmEngine.hpp"
#include "AziHsmDigestSignVerify.hpp"
#include "AziHsmPKeyEc.hpp"
#include "AziHsmHash.hpp"
#include "AziHsmPKeys.hpp"

AziHsmDigestSignVerify::AziHsmDigestSignVerify(ENGINE *e, EVP_PKEY *pkey, AziHsmShaHashType hash_type)
    : e(e), pkey(pkey), hash(hash_type)
{
    if (pkey == nullptr)
    {
        throw std::runtime_error("pkey is null");
    }
}

int AziHsmDigestSignVerify::sign(std::vector<unsigned char> &sig, const std::vector<unsigned char> &data)
{
    int ret;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(this->pkey, this->e);
    if (pctx == nullptr)
    {
        return 0;
    }
    AziHsmEvpMdCtx md_ctx(pctx);

    if ((ret = EVP_DigestSignInit(md_ctx.getCtx(), nullptr, this->hash.getType(), nullptr, nullptr)) != 1)
    {
        return ret;
    }

    if ((ret = EVP_DigestSignUpdate(md_ctx.getCtx(), data.data(), data.size())) != 1)
    {
        return ret;
    }

    size_t sig_len = 0;
    if ((ret = EVP_DigestSignFinal(md_ctx.getCtx(), NULL, &sig_len)) != 1)
    {
        return ret;
    }

    sig.resize(sig_len);

    return EVP_DigestSignFinal(md_ctx.getCtx(), sig.data(), &sig_len);
}

int AziHsmDigestSignVerify::verify(const std::vector<unsigned char> &sig, const std::vector<unsigned char> &data)
{
    int ret;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(this->pkey, this->e);
    if (pctx == nullptr)
    {
        return 0;
    }
    AziHsmEvpMdCtx md_ctx(pctx);

    if ((ret = EVP_DigestVerifyInit(md_ctx.getCtx(), nullptr, this->hash.getType(), nullptr, nullptr)) != 1)
    {
        return ret;
    }

    if ((ret = EVP_DigestVerifyUpdate(md_ctx.getCtx(), data.data(), data.size())) != 1)
    {
        return ret;
    }

    return EVP_DigestVerifyFinal(md_ctx.getCtx(), sig.data(), sig.size());
}
