// Copyright (C) Microsoft Corporation. All rights reserved.

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>

// ECC
#include <openssl/ec.h>
#include <openssl/evp.h>

// These constants are needed, but bindgen doesn't pick them up.
// So export them this way.
const unsigned long DYNAMIC_VERSION = OSSL_DYNAMIC_VERSION;
const unsigned long DYNAMIC_OLDEST = OSSL_DYNAMIC_OLDEST;
const unsigned long ENGINE_CTRL_FLAG_INTERNAL = ENGINE_CMD_FLAG_INTERNAL;
const unsigned long ENGINE_CTRL_FLAG_NUMERIC = ENGINE_CMD_FLAG_NUMERIC;
const unsigned long ENGINE_CTRL_FLAG_STRING = ENGINE_CMD_FLAG_STRING;
const unsigned long OPENSSL_VER = OPENSSL_VERSION_NUMBER;
