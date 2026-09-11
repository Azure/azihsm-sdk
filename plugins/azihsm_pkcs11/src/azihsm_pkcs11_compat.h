// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Cryptoki platform-macro definitions plus the canonical header include. The
 * OASIS PKCS#11 v3.1 headers require the consumer to define five platform macros
 * before inclusion; centralising them here gives every translation unit an
 * identical ABI.
 */

#pragma once

/* The five mandatory Cryptoki platform macros (UNIX definitions). */
#define CK_PTR *

#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

/*
 * Structure packing. The Cryptoki spec's example uses 1-byte packing, but the
 * DE-FACTO ABI on every mainstream Linux consumer (OpenSC/pkcs11-tool, SoftHSM,
 * p11-kit, NSS, GnuTLS/p11tool) is the compiler's NATURAL alignment — because
 * they all include the headers without a pack pragma on UNIX. Packing 1-byte
 * here would shift every function pointer in CK_FUNCTION_LIST (whose leading
 * CK_VERSION is 2 bytes) and make the module ABI-incompatible with those tools
 * (observed: immediate SIGSEGV in pkcs11-tool). So: pack only on Windows, where
 * the ecosystem does use #pragma pack(1).
 */
#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#endif
#include "pkcs11.h"
#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif
