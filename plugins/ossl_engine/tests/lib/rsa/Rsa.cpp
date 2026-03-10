// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmRsa.hpp"
#include <stdexcept>
#include <vector>
#include <memory>

int rsa_keys_compare(const RSA *rsa1, const RSA *rsa2)
{
    const BIGNUM *n1, *e1, *n2, *e2;
    if (rsa1 == nullptr || rsa2 == nullptr)
    {
        return -1;
    }

    /* Get the public key components of the first RSA key */
    RSA_get0_key(rsa1, &n1, &e1, NULL);

    /* Get the public key components of the second RSA key */
    RSA_get0_key(rsa2, &n2, &e2, NULL);

    /* Compare the modulus */
    if (BN_cmp(n1, n2) != 0)
    {
        return 1; // Modulus does not match
    }

    /* Compare the public exponent */
    if (BN_cmp(e1, e2) != 0)
    {
        return 1; // Public exponent does not match
    }

    return 0; // Public portions match
}

AziHsmRsaMethod::AziHsmRsaMethod() : e(nullptr) {}

AziHsmRsaMethod::AziHsmRsaMethod(ENGINE *e)
{
    if (e == nullptr)
    {
        throw std::runtime_error("Engine is null");
    }
    this->e = e;
}

AziHsmRsa::AziHsmRsa(ENGINE *e)
{
    RSA *key = RSA_new_method(e);
    if (key == nullptr)
    {
        throw std::runtime_error("Could not create RSA key");
    }

    this->key = key;
}

AziHsmRsa::AziHsmRsa(const std::vector<unsigned char> &der)
{
    const unsigned char *data = (const unsigned char *)der.data();
    auto pkey_deleter = [](EVP_PKEY *p)
    { if(p != nullptr) { EVP_PKEY_free(p); } };
    std::unique_ptr<EVP_PKEY, decltype(pkey_deleter)> pkey(
        d2i_PrivateKey(NID_rsaEncryption, nullptr, &data, der.size()), pkey_deleter);

    if (pkey.get() == nullptr)
    {
        throw std::runtime_error("Could not create private key");
    }

    RSA *key = EVP_PKEY_get1_RSA(pkey.get());
    if (key == nullptr)
    {
        throw std::runtime_error("Could not create RSA key");
    }

    this->key = key;
}

RSA *AziHsmRsa::getKey()
{
    return this->key;
}

AziHsmRsa::~AziHsmRsa()
{
    if (this->key != nullptr)
    {
        RSA_free(this->key);
    }
}

int AziHsmRsa::encrypt(std::vector<unsigned char> &encrypted, const std::vector<unsigned char> &decrypted)
{
    encrypted.resize(RSA_size(this->key));
    int len = RSA_public_encrypt(decrypted.size(), decrypted.data(), encrypted.data(), this->key, RSA_PKCS1_OAEP_PADDING);
    if (len >= 0)
    {
        encrypted.resize(len);
    }

    return len;
}

int AziHsmRsa::decrypt(std::vector<unsigned char> &decrypted, const std::vector<unsigned char> &encrypted)
{
    decrypted.resize(RSA_size(this->key));
    int len = RSA_private_decrypt(encrypted.size(), encrypted.data(), decrypted.data(), this->key, RSA_PKCS1_OAEP_PADDING);
    if (len >= 0)
    {
        decrypted.resize(len);
    }

    return len;
}

int AziHsmRsa::sign(int nid, std::vector<unsigned char> &sig, const std::vector<unsigned char> &in)
{
    sig.resize(RSA_size(this->key));
    unsigned int siglen;
    int ret = RSA_sign(nid, in.data(), (unsigned int)in.size(), sig.data(), &siglen, this->key);
    if (ret >= 0)
    {
        sig.resize(siglen);
    }

    return ret;
}

int AziHsmRsa::verify(int nid, const std::vector<unsigned char> &sig, const std::vector<unsigned char> &in)
{
    return RSA_verify(nid, in.data(), (unsigned int)in.size(), sig.data(), (unsigned int)sig.size(), this->key);
}