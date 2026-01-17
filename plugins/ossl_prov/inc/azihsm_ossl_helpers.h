// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _Return_type_success_
#define _Return_type_success_(expr)
#endif

typedef _Return_type_success_(return == 1) int OSSL_STATUS;

// Macros giving readable name to return values in functions returning OSSL_STATUS
#define OSSL_SUCCESS (1)
#define OSSL_FAILURE (0)

#ifdef __cplusplus
}
#endif
