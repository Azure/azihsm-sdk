// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmCiphers.hpp"
#include <cstring>

// AziHsmAesCipher Class Implementation

AziHsmAesCipher::AziHsmAesCipher(ENGINE *e, int nid, int mode, int iv_len)
{
    this->e = e;
    this->cipher = ENGINE_get_cipher(e, nid);
    this->nid = nid;
    this->mode = mode;
    this->iv_len = iv_len;
    validate();
}

const EVP_CIPHER *AziHsmAesCipher::getCipher()
{
    return this->cipher;
}

int AziHsmAesCipher::getNid()
{
    return this->nid;
}

void AziHsmAesCipher::validate()
{
    if (cipher == nullptr)
    {
        throw std::runtime_error("No Cipher found");
    }
    if (EVP_CIPHER_nid(cipher) != nid)
    {
        throw std::runtime_error("NID mismatch");
    }
    if (EVP_CIPHER_mode(cipher) != mode)
    {
        throw std::runtime_error("Aes Mode mismatch");
    }
    if (EVP_CIPHER_block_size(cipher) != 16)
    {
        throw std::runtime_error("Block size mismatch");
    }
    if (EVP_CIPHER_iv_length(cipher) != iv_len)
    {
        throw std::runtime_error("IV length mismatch");
    }
    if (EVP_CIPHER_key_length(cipher) != 8)
    {
        throw std::runtime_error("Key length mismatch");
    }
    if (EVP_CIPHER_meth_get_init(cipher) == nullptr)
    {
        throw std::runtime_error("Init method not found");
    }
    if (EVP_CIPHER_meth_get_ctrl(cipher) == nullptr)
    {
        throw std::runtime_error("Ctrl method not found");
    }
    if (EVP_CIPHER_meth_get_cleanup(cipher) == nullptr)
    {
        throw std::runtime_error("Cleanup method not found");
    }
}

// AziHsmAesCipherCtx Class Implementation

AziHsmAesCipherCtx::AziHsmAesCipherCtx()
{
    this->e = nullptr;
    this->cipher = AziHsmAesCipher();
    this->nid = 0;
    this->encrypting = 0;
    this->ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
    {
        throw std::runtime_error("Failed to allocate CTX");
    }
    this->current_key = std::vector<unsigned char>();
}

AziHsmAesCipherCtx::~AziHsmAesCipherCtx()
{
    EVP_CIPHER_CTX_free(ctx);
}

EVP_CIPHER_CTX *AziHsmAesCipherCtx::getCtx()
{
    return this->ctx;
}

ENGINE *AziHsmAesCipherCtx::getEngine()
{
    return this->e;
}

AziHsmAesCipher AziHsmAesCipherCtx::getCipher()
{
    return this->cipher;
}

int AziHsmAesCipherCtx::getNid()
{
    return this->nid;
}

int AziHsmAesCipherCtx::isEncrypting()
{
    return this->encrypting;
}

const unsigned char *AziHsmAesCipherCtx::getCurrentKey()
{
    return this->current_key.data();
}

int AziHsmAesCipherCtx::nid_to_mode(int nid)
{
    switch (nid)
    {
    case NID_aes_128_cbc:
    case NID_aes_192_cbc:
    case NID_aes_256_cbc:
        return EVP_CIPH_CBC_MODE;
    case NID_aes_256_gcm:
        return EVP_CIPH_GCM_MODE;
    case NID_aes_256_xts:
        return EVP_CIPH_XTS_MODE;
    default:
        return -1;
    }
}

int AziHsmAesCipherCtx::nid_to_iv_len(int nid)
{
    switch (nid)
    {
    case NID_aes_128_cbc:
    case NID_aes_192_cbc:
    case NID_aes_256_cbc:
    case NID_aes_256_xts:
        return 16;
    case NID_aes_256_gcm:
        return 12;
    default:
        return -1;
    }
}

int AziHsmAesCipherCtx::init(ENGINE *e, int nid, int encrypting, const unsigned char *key, const unsigned char *iv)
{
    this->e = e;
    int mode = nid_to_mode(nid);
    int iv_len = nid_to_iv_len(nid);
    this->cipher = AziHsmAesCipher(e, nid, mode, iv_len);
    this->nid = nid;
    this->encrypting = encrypting;
    if (EVP_CipherInit_ex(ctx, cipher.getCipher(), e, key, iv, encrypting) == 1)
    {
        validate();
        return 1;
    }

    return 0;
}

int AziHsmAesCipherCtx::keygen(int encrypting)
{
    int key_len = EVP_CIPHER_CTX_key_length(ctx);
    std::vector<unsigned char> key(key_len);
    this->encrypting = encrypting;

    if (EVP_CIPHER_CTX_rand_key(ctx, key.data()) != 1)
    {
        return 0;
    }

    if (current_key.size() > 0)
    {
        if (std::memcmp(current_key.data(), key.data(), key.size()) == 0)
        {
            return 0;
        }
    }

    if (init(e, nid, encrypting, key.data(), nullptr) != 1)
    {
        return 0;
    }

    current_key = key;
    return 1;
}

int AziHsmAesCipherCtx::copy(AziHsmAesCipherCtx &source)
{
    e = source.getEngine();
    cipher = source.getCipher();
    nid = source.getNid();
    encrypting = source.isEncrypting();
    const unsigned char *src_key = source.getCurrentKey();
    for (int i = 0; i < current_key.size(); i++)
    {
        current_key.push_back(src_key[i]);
    }

    if (EVP_CIPHER_CTX_copy(ctx, source.getCtx()) != 1)
    {
        return 0;
    }

    validate();
    return 1;
}

int AziHsmAesCipherCtx::encrypt(const unsigned char *pdata, int pdatalen, const unsigned char *iv, std::vector<unsigned char> &cdata)
{
    if (EVP_EncryptInit_ex(ctx, cipher.getCipher(), e, current_key.data(), iv) != 1)
    {
        return 0;
    }

    if (EVP_CIPHER_CTX_encrypting(ctx) != 1)
    {
        return 0;
    }

    int BLOCK_SIZE = EVP_CIPHER_CTX_block_size(ctx);

    // Padding is enabled by default. So, add a block size to the data length
    cdata.resize(pdatalen + BLOCK_SIZE);
    int len;
    int cdata_len;

    if (EVP_EncryptUpdate(ctx, (unsigned char *)&cdata[0], &len, pdata, pdatalen) == 1)
    {
        cdata_len = len;
        if (EVP_EncryptFinal_ex(ctx, (unsigned char *)&cdata[0] + len, &len) == 1)
        {
            cdata_len += len;
            cdata.resize(cdata_len);
            return 1;
        }
    }

    return 0;
}

int AziHsmAesCipherCtx::decrypt(const unsigned char *cdata, int cdatalen, const unsigned char *iv, std::vector<unsigned char> &pdata)
{
    if (EVP_DecryptInit_ex(ctx, cipher.getCipher(), e, current_key.data(), iv) != 1)
    {
        return 0;
    }

    if (EVP_CIPHER_CTX_encrypting(ctx) != 0)
    {
        return 0;
    }

    int BLOCK_SIZE = EVP_CIPHER_CTX_block_size(ctx);
    pdata.resize(cdatalen + BLOCK_SIZE);
    int len;
    int pdata_len;

    if (EVP_DecryptUpdate(ctx, (unsigned char *)&pdata[0], &len, cdata, cdatalen) == 1)
    {
        pdata_len = len;
        if (EVP_CipherFinal_ex(ctx, (unsigned char *)&pdata[0] + len, &len) == 1)
        {
            pdata_len += len;
            pdata.resize(pdata_len);
            return 1;
        }
    }

    return 0;
}

int AziHsmAesCipherCtx::auth_encrypt(const unsigned char *pdata, int pdatalen, const unsigned char *iv, std::vector<unsigned char> aad, std::vector<unsigned char> &cdata)
{
    if (EVP_EncryptInit_ex(ctx, cipher.getCipher(), e, current_key.data(), iv) != 1)
    {
        return 0;
    }

    if (EVP_CIPHER_CTX_encrypting(ctx) != 1) {
        return 0;
    }

    int BLOCK_SIZE = EVP_CIPHER_CTX_block_size(ctx);
    int len;

    if (aad.size() > 0)
    {
        // Set AAD
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
        {
            return 0;
        }
    }

    // Padding is enabled by default. So, add a block size to the data length
    cdata.resize(pdatalen + BLOCK_SIZE);
    int cdata_len;

    len = 0;

    if (EVP_EncryptUpdate(ctx, (unsigned char *)&cdata[0], &len, pdata, pdatalen) == 1)
    {
        cdata_len = len;
        if (EVP_EncryptFinal_ex(ctx, (unsigned char *)&cdata[0] + len, &len) == 1)
        {
            cdata_len += len;
            cdata.resize(cdata_len);
            return 1;
        }
    }

    return 0;
}

int AziHsmAesCipherCtx::auth_decrypt(const unsigned char *cdata, int cdatalen, const unsigned char *iv, std::vector<unsigned char> aad, std::vector<unsigned char> &pdata)
{
    if (EVP_DecryptInit_ex(ctx, cipher.getCipher(), e, current_key.data(), iv) != 1)
    {
        return 0;
    }

    if (EVP_CIPHER_CTX_encrypting(ctx) != 0)
    {
        return 0;
    }

    int BLOCK_SIZE = EVP_CIPHER_CTX_block_size(ctx);
    int len;

    if (aad.size() > 0)
    {
        // Set AAD
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
        {
            return 0;
        }
    }

    pdata.resize(cdatalen + BLOCK_SIZE);
    int pdata_len;

    if (EVP_DecryptUpdate(ctx, (unsigned char *)&pdata[0], &len, cdata, cdatalen) == 1)
    {
        pdata_len = len;
        if (EVP_CipherFinal_ex(ctx, (unsigned char *)&pdata[0] + len, &len) == 1)
        {
            pdata_len += len;
            pdata.resize(pdata_len);
            return 1;
        }
    }

    return 0;
}

int AziHsmAesCipherCtx::ctrl(int cmd, int arg, std::vector<unsigned char> &data)
{
    if (data.size() == 0)
    {
        return EVP_CIPHER_CTX_ctrl(ctx, cmd, arg, nullptr);
    }
    else
    {
        return EVP_CIPHER_CTX_ctrl(ctx, cmd, arg, data.data());
    }
}

void AziHsmAesCipherCtx::validate()
{
#ifdef OPENSSL_3
    if (EVP_CIPHER_CTX_get0_cipher(ctx) != cipher.getCipher())
    {
        throw std::runtime_error("Cipher mismatch");
    }

    if (EVP_CIPHER_CTX_get_nid(ctx) != nid)
    {
        throw std::runtime_error("NID mismatch");
    }

    if (EVP_CIPHER_CTX_is_encrypting(ctx) != encrypting)
    {
        throw std::runtime_error("Encrypting flag mismatch");
    }
#else
    if (EVP_CIPHER_CTX_cipher(ctx) != cipher.getCipher())
    {
        throw std::runtime_error("Cipher mismatch");
    }

    if (EVP_CIPHER_CTX_nid(ctx) != nid)
    {
        throw std::runtime_error("NID mismatch");
    }

    if (EVP_CIPHER_CTX_encrypting(ctx) != encrypting)
    {
        throw std::runtime_error("Encrypting flag mismatch");
    }
#endif
    if (EVP_CIPHER_CTX_block_size(ctx) != 16)
    {
        throw std::runtime_error("Block size mismatch");
    }

    if (EVP_CIPHER_CTX_iv_length(ctx) != nid_to_iv_len(nid))
    {
        throw std::runtime_error("IV length mismatch");
    }

    if (EVP_CIPHER_CTX_key_length(ctx) != 8)
    {
        throw std::runtime_error("Key length mismatch");
    }
}
