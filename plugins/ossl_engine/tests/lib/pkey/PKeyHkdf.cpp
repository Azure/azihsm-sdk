// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmEc.hpp"
#include "AziHsmPKeyEc.hpp"
#include "AziHsmPKeyHkdf.hpp"
#include "AziHsmCiphers.hpp"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

AziHsmHkdf::AziHsmHkdf(ENGINE *e, std::vector<unsigned char> secret, int key_type, int md, bool hkdf = true)
    : AziHsmPKeyCtx(EVP_PKEY_HKDF, e)
{
    this->secret = secret;
    this->key_type = key_type;
    this->hkdf = hkdf;
    this->md = md;
    const EVP_CIPHER *cipher = EVP_get_cipherbynid(key_type);
    if (cipher == nullptr)
    {
        throw std::runtime_error("Invalid Cipher NID");
    }
    this->aes_key_len = EVP_CIPHER_key_length(cipher);
    if (this->aes_key_len == 0)
    {
        throw std::runtime_error("Invalid AES key length");
    }

    this->prk_len = EVP_MD_size(EVP_get_digestbynid(md));
    if (this->prk_len == 0)
    {
        throw std::runtime_error("Invalid Prk length");
    }
}

int AziHsmHkdf::derive(std::vector<unsigned char> &salt, std::vector<unsigned char> &info, std::vector<unsigned char> &aes_key)
{
    if (EVP_PKEY_derive_init(this->getCtx()) != 1)
    {
        return 0;
    }

    if (!this->hkdf && this->ctrl(-1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_CUSTOM_KBKDF, 0, nullptr) != 1)
    {
        return 0;
    }

    const EVP_MD *md = EVP_get_digestbynid(this->md);
    if (md == nullptr)
    {
        return 0;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(this->getCtx(), md) != 1)
    {
        return 0;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(this->getCtx(), salt.data(), salt.size()) != 1)
    {
        return 0;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(this->getCtx(), this->secret.data(), this->secret.size()) != 1)
    {
        return 0;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(this->getCtx(), info.data(), info.size()) != 1)
    {
        return 0;
    }

    size_t out_len = aes_key.size();
    if (EVP_PKEY_derive(this->getCtx(), aes_key.data(), &out_len) != 1)
    {
        return 0;
    }
    aes_key.resize(out_len);
    return 1;
}

int AziHsmHkdf::expand(std::vector<unsigned char> &salt, std::vector<unsigned char> &info, std::vector<unsigned char> &prk, std::vector<unsigned char> &aes_key)
{
    if (EVP_PKEY_derive_init(this->getCtx()) != 1)
    {
        return 0;
    }

    if (!this->hkdf && this->ctrl(-1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_CUSTOM_KBKDF, 0, nullptr) != 1)
    {
        return 0;
    }

    const EVP_MD *md = EVP_get_digestbynid(this->md);
    if (md == nullptr)
    {
        return 0;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(this->getCtx(), md) != 1)
    {
        return 0;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(this->getCtx(), prk.data(), prk.size()) != 1)
    {
        return 0;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(this->getCtx(), info.data(), info.size()) != 1)
    {
        return 0;
    }

    if (EVP_PKEY_CTX_hkdf_mode(this->getCtx(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1)
    {
        return 0;
    }

    if (this->ctrl(-1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_CUSTOM_KEY_TYPE, key_type, nullptr) != 1)
    {
        return 0;
    }

    size_t out_len = aes_key.size();
    if (EVP_PKEY_derive(this->getCtx(), aes_key.data(), &out_len) != 1)
    {
        return 0;
    }
    prk.resize(out_len);
    return 1;
}

// Helper function to determine secret size based on curve_name
int AziHsmHkdf::getSecretSize(int curve_name)
{
    if (curve_name == NID_X9_62_prime256v1)
    {
        return 256;
    }
    else if (curve_name == NID_secp384r1)
    {
        return 384;
    }
    else if (curve_name == NID_secp521r1)
    {
        return 521;
    }
    throw std::runtime_error("Unsupported curve_name");
}