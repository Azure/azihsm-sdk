// Copyright (c) Microsoft Corporation. All rights reserved.
#ifndef AZIHSM_PKEY_EC_HPP
#define AZIHSM_PKEY_EC_HPP

#include "AziHsmPKeys.hpp"
#include "AziHsmEc.hpp"

class AziHsmPKeyEcCtx : public AziHsmPKeyCtx
{
public:
    AziHsmPKeyEcCtx(ENGINE *e, int curve_name);

    AziHsmPKeyEcCtx(ENGINE *e, EVP_PKEY *pkey, bool param = false);

    // Member functions
    EVP_PKEY *keygen(bool from_param = true, bool ecdh = false);

    AziHsmPKeyEcCtx copy();

    int derive(EVP_PKEY *peer, std::vector<unsigned char> &secret);
    
    EVP_PKEY *paramgen();
    EVP_PKEY *keygen(EVP_PKEY *param, bool ecdh = false);

    void setCurveName(int curve_name) { this->curve_name = curve_name; };
    void validateEcPKey(EVP_PKEY *pkey);
private:
    void init(int curve_name);

    int curve_name;
};

#endif // AZIHSM_PKEY_EC_HPP
