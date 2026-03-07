// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef OSSL_HELPERS_HPP
#define OSSL_HELPERS_HPP

#include <memory>
#include <openssl/evp.h>

// ---------------------------------------------------------------------------
// Smart-pointer deleters for OpenSSL C objects
// ---------------------------------------------------------------------------

struct EvpPkeyCtxDeleter
{
    void operator()(EVP_PKEY_CTX *p) const
    {
        EVP_PKEY_CTX_free(p);
    }
};
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

struct EvpPkeyDeleter
{
    void operator()(EVP_PKEY *p) const
    {
        EVP_PKEY_free(p);
    }
};
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

struct EvpMdCtxDeleter
{
    void operator()(EVP_MD_CTX *p) const
    {
        EVP_MD_CTX_free(p);
    }
};
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

#endif // OSSL_HELPERS_HPP
