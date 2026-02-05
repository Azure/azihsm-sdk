// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <openssl/core_dispatch.h>

/*
 * RSA Signature Operations for azihsm Provider
 *
 * Placeholder implementation. Full RSA signature support coming soon.
 * For now, we provide stub dispatch table to allow provider to load.
 */

/* Stub dispatch table - RSA signatures not yet implemented */
const OSSL_DISPATCH azihsm_ossl_rsa_signature_functions[] = {
    { 0, NULL }, /* Empty dispatch table - RSA signatures TODO */
};
