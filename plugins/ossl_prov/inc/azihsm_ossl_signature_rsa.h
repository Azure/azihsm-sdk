// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <openssl/core_dispatch.h>
#include <openssl/evp.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_rsa.h"

/* RSA padding modes */
#define AZIHSM_RSA_PAD_MODE_PKCSV15 0
#define AZIHSM_RSA_PAD_MODE_PSS 1

/* Special salt length values (matching OpenSSL's RSA_PSS_SALTLEN_* constants) */
#define AZIHSM_RSA_PSS_SALTLEN_DIGEST -1 /* Salt length equals hash length */
#define AZIHSM_RSA_PSS_SALTLEN_AUTO -2   /* Auto-detect on verify */
#define AZIHSM_RSA_PSS_SALTLEN_MAX -3    /* Maximum possible salt */

/* Signature context for RSA operations */
typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx; /* Provider context */
    AZIHSM_RSA_KEY *key;           /* RSA key (public or private) */
    const EVP_MD *md;              /* Hash algorithm (SHA1, SHA256, etc.) */
    int operation;                 /* Sign (1) or Verify (0) */
    azihsm_handle sign_ctx;        /* HSM streaming sign/verify context */

    /* PSS-specific fields */
    int pad_mode;          /* AZIHSM_RSA_PAD_MODE_PKCSV15 or _PSS */
    const EVP_MD *mgf1_md; /* MGF1 hash (defaults to md if NULL) */
    int salt_len;          /* PSS salt length (-1 = digest len) */
} azihsm_rsa_sig_ctx;

/* Dispatch tables */
extern const OSSL_DISPATCH azihsm_ossl_rsa_signature_functions[];