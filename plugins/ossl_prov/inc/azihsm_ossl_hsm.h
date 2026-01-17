// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <azihsm.h>

void azihsm_close_device_and_session(azihsm_handle device, azihsm_handle session);
azihsm_error azihsm_open_device_and_session(azihsm_handle *device, azihsm_handle *session);

#ifdef __cplusplus
}
#endif
