// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>

// Security-domain provisioning helper for the TBOR sealing round-trip test.
//
// A complete `SdSealingKeyGen` round trip needs a partition in the
// `Initialized` lifecycle state on a Crypto-Officer session. Reaching that
// state requires the full TBOR provisioning flow — rotate the CO PSK,
// `PartInit`, build a POTA-anchored PTA certificate chain, `PartFinal` —
// exactly the sequence a real C SDK consumer performs (except the consumer
// supplies their own PKI-issued chain instead of synthesizing one).
//
// The chain is built with the platform host crypto (no HSM session):
// OpenSSL on Linux, BCrypt on Windows. This is gated to the emu backend
// (the flow is only meaningful against the in-process firmware).
#if defined(AZIHSM_FEATURE_EMU)

/// Provision a freshly-reset partition's security domain and return a live,
/// provisioned Crypto-Officer session handle (`Initialized` state).
///
/// Steps: open a CO session under the default PSK, rotate it, reopen under
/// the rotated PSK, `PartInit`, build a POTA-anchored root -> PTA chain from
/// the returned CSR, then `PartFinal`.
///
/// Records a gtest failure and returns 0 on any error. On success the caller
/// owns the returned session handle and must close it with
/// `azihsm_sess_close`.
///
/// @param part_handle An opened, factory-reset partition handle.
/// @return A provisioned CO session handle, or 0 on failure.
azihsm_handle provision_sd_co_session(azihsm_handle part_handle);

#endif // defined(AZIHSM_FEATURE_EMU)
