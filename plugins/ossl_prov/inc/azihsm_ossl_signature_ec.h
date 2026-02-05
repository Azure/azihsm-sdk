// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <openssl/core_dispatch.h>
#include <openssl/evp.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_ec.h"

/* Signature context for ECDSA operations */
typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx; /* Provider context */
    AZIHSM_EC_KEY *key;            /* EC key (public or private) */
    const EVP_MD *md;              /* Hash algorithm (SHA1, SHA256, etc.) */
    int operation;                 /* Sign (1) or Verify (0) */
    azihsm_handle sign_ctx;        /* HSM streaming sign/verify context */
} azihsm_ec_sig_ctx;

/* Dispatch tables */
extern const OSSL_DISPATCH azihsm_ossl_ecdsa_signature_functions[];
