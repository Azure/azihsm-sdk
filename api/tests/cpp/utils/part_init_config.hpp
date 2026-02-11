// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <cstdint>
#include <vector>

#include "handle/test_creds.hpp"

/// Result of dynamic POTA endorsement generation.
/// Contains a raw r||s signature (96 bytes for P-384) and a DER-encoded
/// SubjectPublicKeyInfo public key.
struct PotaEndorsement
{
    std::vector<uint8_t> signature;
    std::vector<uint8_t> public_key_der;
};

/// Generates a POTA endorsement dynamically.
///
/// On Windows this uses BCrypt/SymCrypt; on Linux it uses OpenSSL.
///
/// 1. Queries the PID public key from the partition via azihsm_part_get_prop
/// 2. Parses the DER SubjectPublicKeyInfo to extract uncompressed point
/// 3. Loads the hardcoded ECC P-384 private key
/// 4. Hashes the uncompressed point with SHA-384
/// 5. Signs the hash with ECDSA P-384
/// 6. Returns the hardcoded public key DER
///
/// @param part_handle The partition handle (must be opened, before init)
/// @return PotaEndorsement containing signature and public key DER
/// @throws std::runtime_error on failure
PotaEndorsement generate_pota_endorsement(azihsm_handle part_handle);

/// Holds all the OBK + POTA configuration needed for azihsm_part_init.
/// All internal buffers and pointers remain valid for the lifetime of this object.
struct PartInitConfig
{
    PotaEndorsement generated;
    azihsm_buffer sig_buf;
    azihsm_buffer pubkey_buf;
    azihsm_pota_endorsement_data pota_data;
    azihsm_pota_endorsement pota_endorsement;
    azihsm_buffer obk_buf;
    azihsm_owner_backup_key_config backup_config;
};

/// Builds the OBK backup config and POTA endorsement for partition init.
///
/// When AZIHSM_USE_TPM is set, both are configured with TPM sources.
/// Otherwise, the hardcoded TEST_OBK is used for the backup key and
/// a POTA endorsement is dynamically generated from the partition's
/// PID public key using the hardcoded signing key.
///
/// @param part_handle The partition handle (must be opened, before init)
/// @param config Output config whose backup_config and pota_endorsement fields
///               can be passed directly to azihsm_part_init. Must be
///               zero-initialized by the caller.
void make_part_init_config(azihsm_handle part_handle, PartInitConfig &config);
