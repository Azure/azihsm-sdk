// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmEc.hpp"
#include <openssl/ec.h>
#include <vector>
#include <stdexcept>
#include <memory>

AziHsmEcKeyMethod::AziHsmEcKeyMethod() : e(nullptr) {}

AziHsmEcKeyMethod::AziHsmEcKeyMethod(ENGINE *e)
{
    if (e == nullptr)
    {
        throw std::runtime_error("Engine is null");
    }
    this->e = e;
}

AziHsmEcKey::AziHsmEcKey(ENGINE *e)
{
    this->key = nullptr;
    this->nid = 0;
    this->e = e;
}

AziHsmEcKey::AziHsmEcKey(EC_KEY *key)
{
    if (key == nullptr)
    {
        throw std::runtime_error("Key is null");
    }
    this->key = key;
    this->nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
    this->e = EC_KEY_get0_engine(key);
    if (this->nid == 0)
    {
        throw std::runtime_error("Failed to get curve name");
    }
}

AziHsmEcKey::~AziHsmEcKey()
{
    if (this->key != nullptr)
    {
        EC_KEY_free(this->key);
    }
}

unsigned int AziHsmEcKey::getSize()
{
    return ECDSA_size(this->key);
}

int AziHsmEcKey::keygen(int nid, bool ecdh)
{
    this->nid = nid;
    this->key = ec_key_new_with_engine(this->e, nid);
    if (this->key == nullptr)
    {
        return 0;
    }

    if (ecdh)
    {
        EC_KEY_set_flags(this->key, EC_FLAG_COFACTOR_ECDH);
    }

    if (EC_KEY_generate_key(this->key) == 1)
    {
        validate();
        return 1;
    }

    return 0;
}

AziHsmEcKey AziHsmEcKey::copy()
{
    EC_KEY *new_key = EC_KEY_new_by_curve_name(this->nid);
    if (EC_KEY_copy(new_key, this->key) == nullptr || new_key == nullptr)
    {
        throw std::runtime_error("Could not copy EC key");
    }

    if (ec_keys_compare(this->key, new_key) != 0)
    {
        throw std::runtime_error("EC keys are not equal");
    }

    return AziHsmEcKey(new_key);
}

int AziHsmEcKey::sign(const std::vector<unsigned char> &dgst, std::vector<unsigned char> &sig)
{
    unsigned int siglen = sig.size();
    int result = ECDSA_sign(0, dgst.data(), dgst.size(), sig.data(), &siglen, this->key);
    if (result == 1)
    {
        sig.resize(siglen);
    }
    return result;
}

int AziHsmEcKey::verify(const std::vector<unsigned char> &dgst, const std::vector<unsigned char> &sig)
{
    return ECDSA_verify(0, dgst.data(), dgst.size(), sig.data(), sig.size(), this->key);
}

ECDSA_SIG *AziHsmEcKey::ecdsa_sig_sign(const std::vector<unsigned char> &dgst)
{
    return ECDSA_do_sign(dgst.data(), dgst.size(), this->key);
}

int AziHsmEcKey::ecdsa_sig_verify(const std::vector<unsigned char> &dgst, const ECDSA_SIG *sig)
{
    return ECDSA_do_verify(dgst.data(), dgst.size(), sig, this->key);
}

EC_KEY *AziHsmEcKey::getKey()
{
    return this->key;
}

int AziHsmEcKey::getNid()
{
    return this->nid;
}

const EC_POINT *AziHsmEcKey::getPublicKey()
{
    return EC_KEY_get0_public_key(this->key);
}

void AziHsmEcKey::validate()
{
    const EC_GROUP *ec_group = EC_KEY_get0_group(this->key);
    if (ec_group == nullptr)
    {
        throw std::runtime_error("EC key has no group");
    }
    if (EC_GROUP_get_curve_name(ec_group) != this->nid)
    {
        throw std::runtime_error("EC key has wrong NID");
    }

    if (EC_KEY_get0_public_key(this->key) == nullptr)
    {
        throw std::runtime_error("EC key has no public key");
    }

    if (EC_KEY_check_key(this->key) != 1)
    {
        throw std::runtime_error("EC key is invalid");
    }
}

int AziHsmEcKey::getSharedSecretSize()
{
    return EC_GROUP_get_degree(EC_KEY_get0_group(this->key));
}
