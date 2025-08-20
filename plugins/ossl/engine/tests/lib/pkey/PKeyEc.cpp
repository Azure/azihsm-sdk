// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmPKeyEc.hpp"
#include <memory>

// AziHsmPKeyEcCtx derived class implementation

AziHsmPKeyEcCtx::AziHsmPKeyEcCtx(ENGINE *e, int curve_name) : AziHsmPKeyCtx(EVP_PKEY_EC, e)
{
    init(curve_name);
    this->curve_name = curve_name;
}

AziHsmPKeyEcCtx::AziHsmPKeyEcCtx(ENGINE *e, EVP_PKEY *pkey, bool param) : AziHsmPKeyCtx(pkey, e)
{
    if (param)
    {
        return;
    }

    EC_KEY *ec_key_ptr = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec_key_ptr == nullptr)
    {
        throw std::runtime_error("Failed to get EC key from PKey");
    }

    AziHsmEcKey ec_key(ec_key_ptr);
    ec_key.validate();

    this->curve_name = ec_key.getNid();
}

void AziHsmPKeyEcCtx::init(int curve_name)
{
    if (EVP_PKEY_paramgen_init(this->getCtx()) <= 0)
    {
        throw std::runtime_error("Failed to initialize paramgen");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(this->getCtx(), curve_name) <= 0)
    {
        throw std::runtime_error("Failed to set curve name");
    }
}

EVP_PKEY *AziHsmPKeyEcCtx::paramgen()
{
    EVP_PKEY *pkey = nullptr;

    if (EVP_PKEY_paramgen(this->getCtx(), &pkey) != 1)
    {
        return nullptr;
    }

    return pkey;
}

EVP_PKEY *AziHsmPKeyEcCtx::keygen(bool from_param, bool ecdh)
{
    if (from_param)
    {
        EVP_PKEY *param_ptr = this->paramgen();
        AziHsmPKey param(param_ptr);
        return keygen(param.getPKey(), ecdh);
    }
    return keygen(nullptr, ecdh);
}

EVP_PKEY *AziHsmPKeyEcCtx::keygen(EVP_PKEY *param, bool ecdh)
{
    int ret;
    EVP_PKEY *pkey = nullptr;

    if (param != nullptr)
    {
        this->setCtx(EVP_PKEY_CTX_new(param, this->getEngine()));
    }

    if (EVP_PKEY_keygen_init(this->getCtx()) != 1)
    {
        return nullptr;
    }

    if (ecdh)
    {
        if (this->ctrl(EVP_PKEY_EC, EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_EC_CUSTOM_USECASE_ECDH, 0, nullptr) != 1)
        {
            return nullptr;
        }
    }

    if (EVP_PKEY_keygen(this->getCtx(), &pkey) == 1)
    {
        validateEcPKey(pkey);
        return pkey;
    }

    return nullptr;
}

AziHsmPKeyEcCtx AziHsmPKeyEcCtx::copy()
{
    EVP_PKEY_CTX *copy_ctx = EVP_PKEY_CTX_dup(this->getCtx());
    if (copy_ctx == nullptr)
    {
        throw std::runtime_error("Copy context is null");
    }

    AziHsmPKeyEcCtx copy_ctx_obj(this->getEngine(), this->curve_name);
    copy_ctx_obj.setCtx(copy_ctx);

    auto ec_key_deleter = [](EC_KEY* p) { if(p != nullptr) { EC_KEY_free(p); } };

    std::unique_ptr<EC_KEY, decltype(ec_key_deleter)>src_ec_key(
        EVP_PKEY_get1_EC_KEY(this->getPKey()), ec_key_deleter);
    if (src_ec_key.get() == nullptr)
    {
        throw std::runtime_error("Could not get source EC key");
    }

    std::unique_ptr<EC_KEY, decltype(ec_key_deleter)>dst_ec_key(
        EVP_PKEY_get1_EC_KEY(copy_ctx_obj.getPKey()), ec_key_deleter);
    if (dst_ec_key.get() == nullptr)
    {
        throw std::runtime_error("Destnation EC key pointer is null");
    }

    if (ec_keys_compare(src_ec_key.get(), dst_ec_key.get()) != 0)
    {
        throw std::runtime_error("Keys do not match");
    }

    return copy_ctx_obj;
}

int AziHsmPKeyEcCtx::derive(EVP_PKEY *peer, std::vector<unsigned char> &secret)
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

void AziHsmPKeyEcCtx::validateEcPKey(EVP_PKEY *pkey)
{
    if (pkey == nullptr)
    {
        throw std::runtime_error("PKey is null");
    }
    EC_KEY *ec_key_ptr = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec_key_ptr == nullptr)
    {
        throw std::runtime_error("EC key is null");
    }
    AziHsmEcKey ec_key(ec_key_ptr);
    ec_key.validate();
}