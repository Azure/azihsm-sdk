// Copyright (c) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_CIPHERS_HPP
#define AZIHSM_CIPHERS_HPP

#include "AziHsmEngine.hpp"
#include <openssl/evp.h>
#include <memory>

class AziHsmAesCipher
{
public:
    AziHsmAesCipher() {};
    AziHsmAesCipher(ENGINE *e, int nid, int mode, int iv_len);
    ~AziHsmAesCipher() {}

    const EVP_CIPHER *getCipher();
    int getNid();

private:
    void validate();
    ENGINE *e;
    const EVP_CIPHER *cipher;
    int nid;
    int mode;
    int iv_len;
};

class AziHsmAesCipherCtx
{
public:
    AziHsmAesCipherCtx();
    ~AziHsmAesCipherCtx();
    EVP_CIPHER_CTX *getCtx();
    ENGINE *getEngine();
    AziHsmAesCipher getCipher();
    int getNid();
    int isEncrypting();
    const unsigned char *getCurrentKey();
    int init(ENGINE *e, int nid, int encrypting, const unsigned char *key, const unsigned char *iv);
    int keygen(int encrypting);
    int copy(AziHsmAesCipherCtx &source);
    int encrypt(const unsigned char *pdata, int pdatalen, const unsigned char *iv, std::vector<unsigned char> &cdata);
    int
    decrypt(const unsigned char *cdata, int cdatalen, const unsigned char *iv, std::vector<unsigned char> &pdata);
    int auth_encrypt(const unsigned char *pdata, int pdatalen, const unsigned char *iv, std::vector<unsigned char> aad, std::vector<unsigned char> &cdata);
    int
    auth_decrypt(const unsigned char *cdata, int cdatalen, const unsigned char *iv, std::vector<unsigned char> aad, std::vector<unsigned char> &pdata);
    int ctrl(int cmd, int arg, std::vector<unsigned char> &data);

private:
    void validate();
    int nid_to_mode(int nid);
    int nid_to_iv_len(int nid);

    EVP_CIPHER_CTX *ctx;
    ENGINE *e;
    AziHsmAesCipher cipher;
    int nid;
    int encrypting;
    std::vector<unsigned char> current_key;
};

#endif // AZIHSM_CIPHERS_HPP
