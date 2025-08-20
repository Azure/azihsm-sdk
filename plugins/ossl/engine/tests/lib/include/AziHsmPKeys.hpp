// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_PKEYS_HPP
#define AZIHSM_PKEYS_HPP

#include "AziHsmEngine.hpp"
#include "AziHsmHash.hpp"
#include <openssl/evp.h>
#include <vector>
#include <memory>

const int EVP_PKEY_CTRL_HKDF_CUSTOM_KEY_TYPE = 0x2000;
const int EVP_PKEY_CTRL_HKDF_CUSTOM_KBKDF = 0x2001;
const int EVP_PKEY_CTRL_EC_CUSTOM_USECASE_ECDH = 0x2003;

class AziHsmPKey
{
public:
    AziHsmPKey() : key(nullptr) {};
    AziHsmPKey(ENGINE *e, const char *name, bool is_ecdh = false);
    AziHsmPKey(EVP_PKEY *key);
    AziHsmPKey(int nid);
    AziHsmPKey(int nid, std::vector<unsigned char> key_data);
    ~AziHsmPKey();

    int getNid();

    EVP_PKEY *getPKey();

private:
    void validate();

    int nid;
    EVP_PKEY *key;
};

class AziHsmPKeyMethod
{
public:
    AziHsmPKeyMethod() : e(nullptr), pkey_method(nullptr) {};
    AziHsmPKeyMethod(ENGINE *e);
    AziHsmPKeyMethod(ENGINE *e, int nid);

    const EVP_PKEY_METHOD *getPKeyMethod();
    int getNid();

private:
    void validate();

    ENGINE *e;
    const EVP_PKEY_METHOD *pkey_method;
    int nid;
};

class AziHsmPKeyCtx
{
public:
    AziHsmPKeyCtx() : e(nullptr), ctx(nullptr) {};
    AziHsmPKeyCtx(EVP_PKEY *key, ENGINE *e);
    AziHsmPKeyCtx(int id, ENGINE *e);
    int derive(EVP_PKEY *peer, std::vector<unsigned char> &secret);

    ~AziHsmPKeyCtx();

    void setCtx(EVP_PKEY_CTX *ctx);
    EVP_PKEY_CTX *getCtx();
    ENGINE *getEngine();
    EVP_PKEY *getPKey();

    int encrypt(std::vector<unsigned char> &out, const std::vector<unsigned char> &in);
    int decrypt(std::vector<unsigned char> &out, const std::vector<unsigned char> &in);
    int sign(std::vector<unsigned char> &sig, const std::vector<unsigned char> &dgst);
    int verify(const std::vector<unsigned char> &sig, const std::vector<unsigned char> &dgst);
    int ctrl(int key_type, int op_type, int cmd, int p1, void *p2);

protected:
    int initEncrypt();
    int doEncrypt(std::vector<unsigned char> &out, const std::vector<unsigned char> &in);

    int initDecrypt();
    int doDecrypt(std::vector<unsigned char> &out, const std::vector<unsigned char> &in);

    int initSign();
    int doSign(std::vector<unsigned char> &sig, const std::vector<unsigned char> &dgst);

    int initVerify();
    int doVerify(const std::vector<unsigned char> &sig, const std::vector<unsigned char> &dgst);

private:
    void validate();
    void freeCtx();

    ENGINE *e;
    EVP_PKEY_CTX *ctx;
};

#endif // AZIHSM_PKEYS_HPP
