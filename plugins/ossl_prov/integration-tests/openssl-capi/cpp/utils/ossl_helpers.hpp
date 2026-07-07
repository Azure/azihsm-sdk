// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef OSSL_HELPERS_HPP
#define OSSL_HELPERS_HPP

#include <memory>
#include <openssl/evp.h>
#include <openssl/kdf.h>

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

struct EvpMdDeleter
{
    void operator()(EVP_MD *p) const
    {
        EVP_MD_free(p);
    }
};
using EvpMdPtr = std::unique_ptr<EVP_MD, EvpMdDeleter>;

struct EvpMacDeleter
{
    void operator()(EVP_MAC *p) const
    {
        EVP_MAC_free(p);
    }
};
using EvpMacPtr = std::unique_ptr<EVP_MAC, EvpMacDeleter>;

struct EvpMacCtxDeleter
{
    void operator()(EVP_MAC_CTX *p) const
    {
        EVP_MAC_CTX_free(p);
    }
};
using EvpMacCtxPtr = std::unique_ptr<EVP_MAC_CTX, EvpMacCtxDeleter>;

struct EvpKdfDeleter
{
    void operator()(EVP_KDF *p) const
    {
        EVP_KDF_free(p);
    }
};
using EvpKdfPtr = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;

struct EvpKdfCtxDeleter
{
    void operator()(EVP_KDF_CTX *p) const
    {
        EVP_KDF_CTX_free(p);
    }
};
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

struct EvpCipherDeleter
{
    void operator()(EVP_CIPHER *p) const
    {
        EVP_CIPHER_free(p);
    }
};
using EvpCipherPtr = std::unique_ptr<EVP_CIPHER, EvpCipherDeleter>;

struct EvpCipherCtxDeleter
{
    void operator()(EVP_CIPHER_CTX *p) const
    {
        EVP_CIPHER_CTX_free(p);
    }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

#endif // OSSL_HELPERS_HPP
