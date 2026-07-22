// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>

// Security-domain provisioning helper for the sealing round-trip test.
//
// `SdSealingKeyGen` needs a partition in the `Initialized` state on a CO
// session, reached via the full provisioning flow (rotate CO PSK ->
// `PartInit` -> POTA-anchored PTA chain -> `PartFinal`) — the same sequence
// a real C consumer performs, except the consumer brings its own PKI chain.
//
// The chain is built with the platform host crypto (OpenSSL on Linux,
// BCrypt on Windows), no HSM session. Gated to the emu backend.
#if defined(AZIHSM_FEATURE_EMU)

/// Provision a freshly-reset partition's security domain and return a live,
/// provisioned Crypto-Officer session handle (`Initialized` state):
/// open CO under the default PSK, rotate it, reopen, `PartInit`, build a
/// POTA-anchored root -> PTA chain from the CSR, then `PartFinal`.
///
/// Records a gtest failure and returns 0 on error. The caller owns the
/// returned handle and must close it with `azihsm_sess_close`.
///
/// @param part_handle An opened, factory-reset partition handle.
/// @return A provisioned CO session handle, or 0 on failure.
azihsm_handle provision_sd_co_session(azihsm_handle part_handle);

#endif // defined(AZIHSM_FEATURE_EMU)
