// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_RSA_HPP
#define AZIHSM_RSA_HPP

#include "AziHsmEngine.hpp"
#include <openssl/rsa.h>
#include <vector>

class AziHsmRsaMethod
{
public:
    AziHsmRsaMethod();
    AziHsmRsaMethod(ENGINE *e);

private:
    ENGINE *e;
};

class AziHsmRsa
{
public:
    AziHsmRsa(ENGINE *e = nullptr);
    AziHsmRsa(const std::vector<unsigned char> &der);
    ~AziHsmRsa();
    RSA *getKey();

    int encrypt(std::vector<unsigned char> &encrypted, const std::vector<unsigned char> &decrypted);
    int decrypt(std::vector<unsigned char> &decrypted, const std::vector<unsigned char> &encrypted);
    int sign(int nid, std::vector<unsigned char> &sig, const std::vector<unsigned char> &in);
    int verify(int nid, const std::vector<unsigned char> &sig, const std::vector<unsigned char> &in);

private:
    RSA *key;
};

int rsa_keys_compare(const RSA *rsa1, const RSA *rsa2);

#endif // AZIHSM_RSA_HPP
