/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 */

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

/* Constants defined as macros that bindgen cannot discover automatically. */
/* Re-export them as typed C constants so bindgen emits them.              */
static const unsigned long OSSL_DYNAMIC_VERSION_CONST = OSSL_DYNAMIC_VERSION;
static const unsigned long OSSL_DYNAMIC_OLDEST_CONST  = OSSL_DYNAMIC_OLDEST;
