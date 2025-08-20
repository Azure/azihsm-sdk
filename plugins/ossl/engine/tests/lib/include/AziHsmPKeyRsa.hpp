// Copyright (C) Microsoft Corporation. All rights reserved.
#ifndef AZIHSM_PKEY_RSA_HPP
#define AZIHSM_PKEY_RSA_HPP

#include "AziHsmEngine.hpp"
#include "AziHsmPKeys.hpp"
#include "AziHsmRsa.hpp"
#include "AziHsmHash.hpp"
#include <stdint.h>
#include "../../../api-interface/azihsm_engine.h"

enum class AziHsmPaddingType
{
    NO_PAD,
    PKCS1_5,
    PSS,
};

class AziHsmPKeyRsaCtx : public AziHsmPKeyCtx
{
public:
    AziHsmPKeyRsaCtx() : AziHsmPKeyCtx() {};
    AziHsmPKeyRsaCtx(EVP_PKEY *key, ENGINE *e) : AziHsmPKeyCtx(key, e) {};
    AziHsmPKeyRsaCtx(ENGINE *e) : AziHsmPKeyCtx(EVP_PKEY_RSA, e) {};

    int encryptRsa(
        std::vector<unsigned char> &out,
        const std::vector<unsigned char> &in,
        AziHsmShaHashType hash_type = AziHsmShaHashType::SHA1);
    int decryptRsa(
        std::vector<unsigned char> &out,
        const std::vector<unsigned char> &in,
        AziHsmShaHashType hash_type = AziHsmShaHashType::SHA1);
    int signRsa(
        std::vector<unsigned char> &sig,
        const std::vector<unsigned char> &dgst,
        AziHsmShaHashType hash_type = AziHsmShaHashType::SHA1,
        AziHsmPaddingType padding_type = AziHsmPaddingType::NO_PAD,
        int salt_len = 0);
    int verifyRsa(
        const std::vector<unsigned char> &sig,
        const std::vector<unsigned char> &dgst,
        AziHsmShaHashType hash_type = AziHsmShaHashType::SHA1,
        AziHsmPaddingType padding_type = AziHsmPaddingType::NO_PAD,
        int salt_len = 0);

    AziHsmPKeyRsaCtx copyRsaCtx();

    int getSignatureMd(AziHsmShaHashType &hash_type);
    int setSignatureMd(AziHsmShaHashType hash_type);

    int getOaepMd(AziHsmShaHashType &hash_type);
    int setOaepMd(AziHsmShaHashType hash_type);

    int getRsaPadding(AziHsmPaddingType &padding_type);
    int setRsaPadding(AziHsmPaddingType padding_type);

    int getRsaPssSaltLen(int &salt_len);
    int setRsaPssSaltLen(int salt_len);
};

#endif // AZIHSM_PKEY_RSA_HPP
