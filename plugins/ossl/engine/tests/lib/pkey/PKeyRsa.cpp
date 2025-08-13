// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmPKeyRsa.hpp"
#include "AziHsmRsa.hpp"
#include "AziHsmHash.hpp"
#include "AziHsmCiphers.hpp"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <memory>

#include "../../../api-interface/azihsm_engine.h"

int AziHsmPKeyRsaCtx::encryptRsa(
    std::vector<unsigned char> &out,
    const std::vector<unsigned char> &in,
    AziHsmShaHashType hash_type)
{
    int ret;
    if ((ret = initEncrypt()) < 1)
    {
        return ret;
    }

    if ((ret = setOaepMd(hash_type)) < 1)
    {
        return ret;
    }

    return doEncrypt(out, in);
}

int AziHsmPKeyRsaCtx::decryptRsa(
    std::vector<unsigned char> &out,
    const std::vector<unsigned char> &in,
    AziHsmShaHashType hash_type)
{
    int ret;
    if ((ret = initDecrypt()) < 1)
    {
        return ret;
    }

    if ((ret = setOaepMd(hash_type)) < 1)
    {
        return ret;
    }

    return doDecrypt(out, in);
}

int AziHsmPKeyRsaCtx::signRsa(
    std::vector<unsigned char> &sig,
    const std::vector<unsigned char> &dgst,
    AziHsmShaHashType hash_type,
    AziHsmPaddingType padding_type,
    int salt_len)
{
    int ret;
    if ((ret = initSign()) < 1)
    {
        return ret;
    }

    if ((ret = setSignatureMd(hash_type)) < 1)
    {
        return ret;
    }

    if ((ret = setRsaPadding(padding_type)) < 1)
    {
        return ret;
    }

    if (padding_type == AziHsmPaddingType::PSS)
    {
        if ((ret = setRsaPssSaltLen(salt_len)) < 1)
        {
            return ret;
        }
    }

    return doSign(sig, dgst);
}

int AziHsmPKeyRsaCtx::verifyRsa(
    const std::vector<unsigned char> &sig,
    const std::vector<unsigned char> &dgst,
    AziHsmShaHashType hash_type,
    AziHsmPaddingType padding_type,
    int salt_len)
{
    int ret;
    if ((ret = initVerify()) < 1)
    {
        return ret;
    }

    if ((ret = setSignatureMd(hash_type)) < 1)
    {
        return ret;
    }

    if ((ret = setRsaPadding(padding_type)) < 1)
    {
        return ret;
    }

    if (padding_type == AziHsmPaddingType::PSS)
    {
        if ((ret = setRsaPssSaltLen(salt_len)) < 1)
        {
            return ret;
        }
    }

    return doVerify(sig, dgst);
}

AziHsmPKeyRsaCtx AziHsmPKeyRsaCtx::copyRsaCtx()
{
    EVP_PKEY_CTX *copy_ctx = EVP_PKEY_CTX_dup(getCtx());
    if (copy_ctx == nullptr)
    {
        throw std::runtime_error("Could not get RSA copy context");
    }

    AziHsmPKeyRsaCtx ctx;
    ctx.setCtx(copy_ctx);

    auto rsa_deleter = [](RSA *r)
    { if (r != nullptr) RSA_free(r); };

    std::unique_ptr<RSA, decltype(rsa_deleter)> src_rsa(EVP_PKEY_get1_RSA(getPKey()), rsa_deleter);
    if (src_rsa.get() == nullptr)
    {
        throw std::runtime_error("Could not get source RSA key");
    }

    std::unique_ptr<RSA, decltype(rsa_deleter)> dst_rsa(EVP_PKEY_get1_RSA(getPKey()), rsa_deleter);
    if (dst_rsa.get() == nullptr)
    {
        throw std::runtime_error("Could not get source RSA key");
    }

    if (rsa_keys_compare(src_rsa.get(), dst_rsa.get()) != 0)
    {
        throw std::runtime_error("RSA keys do not match");
    }

    return ctx;
}

int AziHsmPKeyRsaCtx::getSignatureMd(AziHsmShaHashType &hash_type)
{
    const EVP_MD *md;
    int ret = EVP_PKEY_CTX_get_signature_md(getCtx(), &md);
    if (ret < 1)
    {
        return ret;
    }
    else if (md == nullptr)
    {
        return 0;
    }

    AziHsmShaHash hash(md);
    hash_type = hash.getHashType();

    return 1;
}

int AziHsmPKeyRsaCtx::setSignatureMd(AziHsmShaHashType hash_type)
{
    AziHsmShaHash hash(hash_type);

    const EVP_MD *md = hash.getType();
    if (md == nullptr)
    {
        return 0;
    }

    int ret;
    if ((ret = EVP_PKEY_CTX_set_signature_md(getCtx(), md)) < 1)
    {
        return ret;
    }

    // Validate
    AziHsmShaHashType check_hash_type;
    if ((ret = getSignatureMd(check_hash_type)) < 1)
    {
        return ret;
    }

    return (check_hash_type == hash_type ? 1 : 0);
}

int AziHsmPKeyRsaCtx::getOaepMd(AziHsmShaHashType &hash_type)
{
    const EVP_MD *md;
    int ret = EVP_PKEY_CTX_get_rsa_oaep_md(getCtx(), &md);
    if (ret < 1)
    {
        return ret;
    }
    else if (md == nullptr)
    {
        return 0;
    }

    AziHsmShaHash hash(md);
    hash_type = hash.getHashType();

    return 1;
}

int AziHsmPKeyRsaCtx::setOaepMd(AziHsmShaHashType hash_type)
{
    if (hash_type == AziHsmShaHashType::SHA1)
    {
        // No-op as this is the default
        return 1;
    }

    AziHsmShaHash hash(hash_type);

    const EVP_MD *md = hash.getType();
    if (md == nullptr)
    {
        return 0;
    }

    int ret;
    if ((ret = EVP_PKEY_CTX_set_rsa_oaep_md(getCtx(), md)) < 1)
    {
        return ret;
    }

    // Validate
    AziHsmShaHashType check_hash_type;
    if ((ret = getOaepMd(check_hash_type)) < 1)
    {
        return ret;
    }

    return (check_hash_type == hash_type ? 1 : 0);
}

int AziHsmPKeyRsaCtx::getRsaPadding(AziHsmPaddingType &padding_type)
{
    int padding, ret;
    if ((ret = EVP_PKEY_CTX_get_rsa_padding(getCtx(), &padding)) < 1)
    {
        return ret;
    }

    switch (padding)
    {
    case 0:
        padding_type = AziHsmPaddingType::NO_PAD;
        break;
    case RSA_PKCS1_PADDING:
        padding_type = AziHsmPaddingType::PKCS1_5;
        break;
    case RSA_PKCS1_PSS_PADDING:
        padding_type = AziHsmPaddingType::PSS;
        break;
    default:
        return 0;
    }

    return 1;
}

int AziHsmPKeyRsaCtx::setRsaPadding(AziHsmPaddingType padding_type)
{
    int padding;
    switch (padding_type)
    {
    case AziHsmPaddingType::NO_PAD:
        // Default
        return 1;
    case AziHsmPaddingType::PKCS1_5:
        padding = RSA_PKCS1_PADDING;
        break;
    case AziHsmPaddingType::PSS:
        padding = RSA_PKCS1_PSS_PADDING;
        break;
    }

    int ret;
    if ((ret = EVP_PKEY_CTX_set_rsa_padding(getCtx(), padding)) < 1)
    {
        return ret;
    }

    // Validate
    AziHsmPaddingType check_padding_type;
    if ((ret = getRsaPadding(check_padding_type)) < 1)
    {
        return ret;
    }

    return (check_padding_type == padding_type ? 1 : 0);
}

int AziHsmPKeyRsaCtx::getRsaPssSaltLen(int &salt_len)
{
    int ret, len = 0;
    if ((ret = EVP_PKEY_CTX_get_rsa_pss_saltlen(getCtx(), &len)) < 1)
    {
        return ret;
    }

    salt_len = len;
    return ret;
}

int AziHsmPKeyRsaCtx::setRsaPssSaltLen(int salt_len)
{
    int ret;
    if ((ret = EVP_PKEY_CTX_set_rsa_pss_saltlen(getCtx(), salt_len)) < 1)
    {
        return ret;
    }

    // Validate
    int check_salt_len;
    if ((ret = getRsaPssSaltLen(check_salt_len)) < 1)
    {
        return ret;
    }

    if ((salt_len == -1 || salt_len == -2) && (ret > 0))
    {
        return 1;
    }
    else
    {
        return (check_salt_len == salt_len ? 1 : 0);
    }
}