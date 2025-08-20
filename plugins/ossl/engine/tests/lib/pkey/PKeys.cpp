// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmPKeys.hpp"

// AziHsmPKey Class implementation

AziHsmPKey::AziHsmPKey(ENGINE *e, const char *name, bool is_ecdh)
{
    this->key = ENGINE_load_private_key(e, name, nullptr, (void *)&is_ecdh);
    this->nid = getNid();
    validate();
}

AziHsmPKey::AziHsmPKey(int nid)
{
    this->key = EVP_PKEY_new();
    EVP_PKEY_set_type(this->key, nid);
    this->nid = nid;
}

AziHsmPKey::AziHsmPKey(int nid, std::vector<unsigned char> key_data)
{
    const unsigned char *key_data_ptr = key_data.data();
    this->key = d2i_PrivateKey(nid, nullptr, &key_data_ptr, key_data.size());
    this->nid = nid;
    validate();
}

AziHsmPKey::AziHsmPKey(EVP_PKEY *key)
{
    this->key = key;
#ifdef OPENSSL_3
    this->nid = EVP_PKEY_get_base_id(key);
#else
    this->nid = EVP_PKEY_base_id(key);
#endif
    validate();
}

AziHsmPKey::~AziHsmPKey()
{
    if (this->key != nullptr)
    {
        EVP_PKEY_free(this->key);
    }
}

EVP_PKEY *AziHsmPKey::getPKey()
{
    return this->key;
}

int AziHsmPKey::getNid()
{
#ifdef OPENSSL_3
    return EVP_PKEY_get_base_id(this->key);
#else
    return EVP_PKEY_base_id(this->key);
#endif
}

void AziHsmPKey::validate()
{
    if (this->key == nullptr)
    {
        throw std::runtime_error("Key not created");
    }

    if (getNid() != this->nid)
    {
        throw std::runtime_error("Key has wrong NID");
    }
}

// AziHsmPKeyMethod Class Implementation

AziHsmPKeyMethod::AziHsmPKeyMethod(ENGINE *e)
{
    if (e == nullptr)
    {
        throw std::runtime_error("No engine provided");
    }
    this->e = e;
}

AziHsmPKeyMethod::AziHsmPKeyMethod(ENGINE *e, int nid)
{
    this->e = e;
    this->pkey_method = ENGINE_get_pkey_meth(e, nid);
    this->nid = nid;
    validate();
}

const EVP_PKEY_METHOD *AziHsmPKeyMethod::getPKeyMethod()
{
    return this->pkey_method;
}

int AziHsmPKeyMethod::getNid()
{
    return this->nid;
}

void AziHsmPKeyMethod::validate()
{
    if (this->pkey_method == nullptr)
    {
        throw std::runtime_error("No PKey method found");
    }

    if (this->nid != EVP_PKEY_RSA)
    {
        int (*pinit)(EVP_PKEY_CTX *);
        EVP_PKEY_meth_get_init(this->pkey_method, &pinit);
        if (pinit == nullptr)
        {
            throw std::runtime_error("Init method not found");
        }
    }

    int (*pencrypt)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
    EVP_PKEY_meth_get_encrypt(this->pkey_method, nullptr, &pencrypt);
    if (pencrypt == nullptr)
    {
        throw std::runtime_error("Encrypt method not found");
    }

    int (*pdecrypt)(EVP_PKEY_CTX *ctx, unsigned char *, size_t *, const unsigned char *, size_t);
    EVP_PKEY_meth_get_decrypt(this->pkey_method, nullptr, &pdecrypt);
    if (pdecrypt == nullptr)
    {
        throw std::runtime_error("Decrypt method not found");
    }
}

// AziHsmPKeyCtx Class Implementation

AziHsmPKeyCtx::AziHsmPKeyCtx(EVP_PKEY *key, ENGINE *e)
{
    this->e = e;
    this->ctx = EVP_PKEY_CTX_new(key, e);
    validate();
}

AziHsmPKeyCtx::AziHsmPKeyCtx(int id, ENGINE *e)
{
    this->e = e;
    this->ctx = EVP_PKEY_CTX_new_id(id, e);
}

AziHsmPKeyCtx::~AziHsmPKeyCtx()
{
    freeCtx();
}

void AziHsmPKeyCtx::freeCtx()
{
    if (this->ctx != nullptr)
    {
        EVP_PKEY_CTX_free(this->ctx);
        this->ctx = nullptr;
    }
}

void AziHsmPKeyCtx::setCtx(EVP_PKEY_CTX *ctx)
{
    freeCtx();
    this->ctx = ctx;
}

int AziHsmPKeyCtx::derive(EVP_PKEY *peer, std::vector<unsigned char> &secret)
{
    EVP_PKEY_CTX *ctx = this->getCtx();

    // Check if EVP_PKEY_derive_init succeeds
    if (EVP_PKEY_derive_init(ctx) != 1)
    {
        return 0;
    }

    // Check if setting the peer key succeeds
    if (EVP_PKEY_derive_set_peer(ctx, peer) != 1)
    {
        return 0;
    }

    size_t secret_len;
    // Check if the first derive call succeeds to get the length
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) != 1)
    {
        return 0;
    }

    secret.resize(secret_len);

    // Final derivation check
    return EVP_PKEY_derive(ctx, secret.data(), &secret_len);
}

EVP_PKEY *AziHsmPKeyCtx::getPKey()
{
    return EVP_PKEY_CTX_get0_pkey(this->ctx);
}

EVP_PKEY_CTX *AziHsmPKeyCtx::getCtx()
{
    return this->ctx;
}

ENGINE *AziHsmPKeyCtx::getEngine()
{
    return this->e;
}

int AziHsmPKeyCtx::encrypt(std::vector<unsigned char> &out, const std::vector<unsigned char> &in)
{
    int ret;
    if ((ret = initEncrypt()) < 1)
    {
        return ret;
    }

    return doEncrypt(out, in);
}

int AziHsmPKeyCtx::decrypt(std::vector<unsigned char> &out, const std::vector<unsigned char> &in)
{
    int ret;
    if ((ret = initDecrypt()) < 1)
    {
        return ret;
    }

    return doDecrypt(out, in);
}

int AziHsmPKeyCtx::sign(std::vector<unsigned char> &sig, const std::vector<unsigned char> &dgst)
{
    int ret;
    if ((ret = initSign()) < 1)
    {
        return ret;
    }

    return doSign(sig, dgst);
}

int AziHsmPKeyCtx::verify(const std::vector<unsigned char> &sig, const std::vector<unsigned char> &dgst)
{
    int ret;
    if ((ret = initVerify()) < 1)
    {
        return ret;
    }

    return doVerify(sig, dgst);
}

int AziHsmPKeyCtx::initEncrypt()
{
    return EVP_PKEY_encrypt_init(this->ctx);
}

int AziHsmPKeyCtx::doEncrypt(std::vector<unsigned char> &out, const std::vector<unsigned char> &in)
{
    int ret;
    size_t outlen;
    if ((ret = EVP_PKEY_encrypt(this->ctx, nullptr, &outlen, in.data(), in.size())) < 1)
    {
        return ret;
    }

    out.resize(outlen);

    if ((ret = EVP_PKEY_encrypt(this->ctx, out.data(), &outlen, in.data(), in.size())) < 1)
    {
        return ret;
    }

    return outlen;
}

int AziHsmPKeyCtx::initDecrypt()
{
    return EVP_PKEY_decrypt_init(this->ctx);
}

int AziHsmPKeyCtx::doDecrypt(std::vector<unsigned char> &out, const std::vector<unsigned char> &in)
{
    int ret;
    size_t outlen;
    if ((ret = EVP_PKEY_decrypt(this->ctx, nullptr, &outlen, in.data(), in.size())) < 1)
    {
        return ret;
    }

    out.resize(outlen);

    if ((ret = EVP_PKEY_decrypt(this->ctx, out.data(), &outlen, in.data(), in.size())) < 1)
    {
        return ret;
    }

    return outlen;
}

int AziHsmPKeyCtx::initSign()
{
    return EVP_PKEY_sign_init(this->ctx);
}

int AziHsmPKeyCtx::doSign(std::vector<unsigned char> &sig, const std::vector<unsigned char> &dgst)
{
    int ret;
    size_t siglen;
    if ((ret = EVP_PKEY_sign(this->ctx, nullptr, &siglen, dgst.data(), dgst.size())) < 1)
    {
        return ret;
    }

    sig.resize(siglen);

    return EVP_PKEY_sign(this->ctx, sig.data(), &siglen, dgst.data(), dgst.size());
}

int AziHsmPKeyCtx::initVerify()
{
    return EVP_PKEY_verify_init(this->ctx);
}

int AziHsmPKeyCtx::doVerify(const std::vector<unsigned char> &sig, const std::vector<unsigned char> &dgst)
{
    return EVP_PKEY_verify(this->ctx, sig.data(), sig.size(), dgst.data(), dgst.size());
}

int AziHsmPKeyCtx::ctrl(int keytype, int optype, int cmd, int p1, void *p2)
{
    return EVP_PKEY_CTX_ctrl(this->ctx, keytype, optype, cmd, p1, p2);
}

void AziHsmPKeyCtx::validate()
{
    if (this->ctx == nullptr)
    {
        throw std::runtime_error("Failed to allocate CTX");
    }
}
