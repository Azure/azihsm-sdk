// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "kdf_derive.hpp"

const char *get_hmac_algo_name(azihsm_algo_id hmac_algo_id)
{
    switch (hmac_algo_id)
    {
        case AZIHSM_ALGO_ID_HMAC_SHA1:
            return "SHA1";
        case AZIHSM_ALGO_ID_HMAC_SHA256:
            return "SHA256";
        case AZIHSM_ALGO_ID_HMAC_SHA384:
            return "SHA384";
        case AZIHSM_ALGO_ID_HMAC_SHA512:
            return "SHA512";
        default:
            return "unknown";
    }
}