// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_API_INTERFACE_H
#define AZIHSM_API_INTERFACE_H

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdbool.h>

/// @brief Command number passed to ENGINE_ctrl
typedef enum AziHsmEngineCommandE
{
    /// @brief Command ID to query engine flags
    AZIHSM_CMD_ENGINE_INFO = ENGINE_CMD_BASE,

    /// @brief Command ID to get the current unwrap key
    AZIHSM_CMD_GET_UNWRAP_KEY,

    /// @brief Command ID to get the built-in unwrap key
    AZIHSM_CMD_GET_BUILTIN_UNWRAP_KEY,

    /// @brief Command to import an ECC key with the given EC_KEY
    AZIHSM_CMD_IMPORT_EC_KEY,

    /// @brief Command to import an RSA key with the given RSA key
    AZIHSM_CMD_IMPORT_RSA,

    /// @brief Command to import an AES key with the given EVP_CIPHER_CTX
    AZIHSM_CMD_IMPORT_EVP_CIPHER_CTX,

    /// @brief Command to import an RSA key with the given EVP_PKEY_CTX
    AZIHSM_CMD_IMPORT_EVP_PKEY_CTX_RSA,

    /// @brief Command to import an ECC key with the given EVP_PKEY_CTX
    AZIHSM_CMD_IMPORT_EVP_PKEY_CTX_ECC,

    /// @brief Command to attest builtin unwrapping key
    AZIHSM_CMD_ATTEST_BUILTIN_UNWRAP_KEY,

    /// @brief Command to attest an RSA key with the given RSA key
    AZIHSM_CMD_ATTEST_RSA,

    /// @brief Command to attest an ECC key with the given EC_KEY
    AZIHSM_CMD_ATTEST_EC_KEY,

    /// @brief Command to attest an RSA key with the given EVP_PKEY
    AZIHSM_CMD_ATTEST_EVP_PKEY_RSA,

    /// @brief Command to attest an ECC key with the given EVP_PKEY
    AZIHSM_CMD_ATTEST_EVP_PKEY_ECC,

    /// @brief Command to get AZIHSM Collateral (device certificate chain)
    AZIHSM_CMD_GET_COLLATERAL,

    /// @brief Command to delete a key by name
    AZIHSM_CMD_DELETE_KEY,
} AziHsmEngineCommand;

/// @brief Engine info flags
typedef enum AziHsmEngineFlagsE
{
    AZIHSM_FEATURE_MOCK = 0x1,
} AziHsmEngineFlags;

/// @brief Engine version information
typedef struct AziHsmEngineVersionS
{
    /// @brief OpenSSL version number
    const unsigned long version;

    /// @brief Major version number
    const unsigned int major;

    /// @brief Minor version number
    const unsigned int minor;

    /// @brief Patch version number
    const unsigned int patch;
} AziHsmEngineVersion;

/// @brief Engine information
typedef struct AziHsmEngineInfoS
{
    /// @brief Flags
    const unsigned long long int flags;

    /// @brief OpenSSL version
    AziHsmEngineVersion ossl_version;
} AziHsmEngineInfo;

/// @brief Digest kind of the wrapped key
typedef enum AziHsmDigestKindE
{
    AZIHSM_DIGEST_SHA1 = 1,
    AZIHSM_DIGEST_SHA256 = 2,
    AZIHSM_DIGEST_SHA384 = 3,
    AZIHSM_DIGEST_SHA512 = 4,
} AziHsmDigestKind;

/// @brief Description of what context a key will be used in
///
/// A key's usage must be set at import time, and can only be used for that specific operation.
typedef enum AziHsmKeyUsageE
{
    /// @brief Key is for sign/verify
    AZIHSM_KEY_USAGE_SIGN_VERIFY = 1,

    /// @brief Key is for encrypt/decrypt
    AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT = 2,

    /// @brief Key is for ECDH derivation
    AZIHSM_KEY_USAGE_DERIVE = 4,
} AziHsmKeyUsage;

/// @brief AZIHSM key availability
typedef enum AziHsmKeyAvailabilityE
{
    /// @brief Availability is for the session
    AZIHSM_AVAILABILITY_SESSION = 0,

    /// @brief Availability is for the app
    AZIHSM_AVAILABILITY_APP = 1,
} AziHsmKeyAvailability;

/// @brief AZIHSM unwrapping key variant
typedef enum AziHsmWrappingKeyTypeE
{
    /// @brief Type is EVP_PKEY
    AZIHSM_UNWRAP_EVP_PKEY = 1,

    /// @brief Type is RSA
    AZIHSM_UNWRAP_RSA = 2,
} AziHsmWrappingKeyType;

/// @brief Structure for importing a key into a context or key structure
typedef struct AziHsmKeyImportS
{
    /// @brief Key sent in by the caller for unwrapped import
    const unsigned char *wrapped_key;

    /// @brief Size of the key data
    size_t wrapped_key_len;

    /// @brief Second key sent in by the caller for unwrapped import (XTS only)
    const unsigned char *wrapped_key2;

    /// @brief Size of the key data (XTS only)
    size_t wrapped_key2_len;

    /// @brief Digest kind
    unsigned int digest_kind;

    /// @brief Key usage
    unsigned int key_usage;

    /// @brief Key availability
    unsigned int key_availability;

    /// @brief Pointer to key name
    const char *key_name;

    /// @brief RSA only: whether or not the key is in CRT format
    bool is_crt;

    /// @brief Structure populated by the command
    void *data;
} AziHsmKeyImport;

/// @brief Structure for getting/setting the unwrap key
typedef struct AziHsmUnwrappingKeyS
{
    /// @brief Key data
    unsigned char *key;

    /// @brief Key data length
    size_t key_len;
} AziHsmUnwrappingKey;

static const unsigned long REPORT_DATA_SIZE = 128;

/// @brief Structure for attesting the RSA/ECC key
typedef struct AziHsmAttestKeyS
{
    /// @brief Key data
    unsigned char *key;

    /// @brief report data
    unsigned char *report_data;

    /// @brief report data length
    size_t report_data_len;

    /// @brief claim data
    unsigned char *claim;

    /// @brief claim data length
    size_t claim_len;
} AziHsmAttestKey;

/// @brief Structure for getting AziHsm device collateral (device certificate chain)
typedef struct AziHsmCollateralS
{
    /// @brief Collateral data (certificate chain)
    unsigned char *collateral;

    /// @brief Collateral data length
    size_t collateral_len;
} AziHsmCollateral;

/// @brief Return global engine information struct
/// @param engine Pointer to OpenSSL engine
/// @return Pointer to info on success, NULL on failure
static inline const AziHsmEngineInfo *azihsm_get_engine_info(ENGINE *engine)
{
    AziHsmEngineInfo *info;

    if (ENGINE_ctrl(engine, AZIHSM_CMD_ENGINE_INFO, 0, (void *)&info, NULL) == 0)
    {
        return NULL;
    }

    return info;
}

/// @brief Get the builtin unwrap key for the AZIHSM engine
/// @param engine Pointer to OpenSSL ENGINE
/// @param key Pointer to key structure to fill out
/// @return 1 on success, 0 on failure
static inline int azihsm_get_builtin_unwrap_key(ENGINE *engine, AziHsmUnwrappingKey *key)
{
    return ENGINE_ctrl(engine, AZIHSM_CMD_GET_BUILTIN_UNWRAP_KEY, 0, (void *)key, NULL);
}

/// @brief Get the unwrap key for the AZIHSM engine
/// @param engine Pointer to OpenSSL ENGINE
/// @param key Pointer to key structure to fill out
/// @return 1 on success, 0 on failure
static inline int azihsm_get_unwrap_key(ENGINE *engine, AziHsmUnwrappingKey *key)
{
    return ENGINE_ctrl(engine, AZIHSM_CMD_GET_UNWRAP_KEY, 0, (void *)key, NULL);
}

/// @brief Unwrap an AES key (non-XTS context)
/// @param engine Pointer to OpenSSL ENGINE
/// @param ctx EVP_CIPHER_CTX structure to populate with the imported key
/// @param nid NID of the cipher used, see Valid NID types for valid uses
/// @param digest_kind Type of digest key is wrapped with
/// @param wrapped_key Blob of wrapped data
/// @param wrapped_key_len Length of blob of wrapped data
/// @param name Pointer to key ID (may be NULL if ephemeral)
/// @param availability Availability of key
/// @return 1 on success, 0 on failure
///
/// @note This function must not be used for keys used for XTS operations
///
/// @section Valid NID types
/// The NID must match the cipher actually being used. Valid types include:
/// * NID_aes_128_cbc
/// * NID_aes_192_cbc
/// * NID_aes_256_cbc
/// * NID_aes_256_gcm
static inline int azihsm_unwrap_aes(
    ENGINE *engine,
    EVP_CIPHER_CTX *ctx,
    int nid,
    AziHsmDigestKind digest_kind,
    const unsigned char *wrapped_key,
    size_t wrapped_key_len,
    const char *name,
    AziHsmKeyAvailability availability)
{
    switch (nid)
    {
    case NID_aes_128_cbc:
    case NID_aes_192_cbc:
    case NID_aes_256_cbc:
    case NID_aes_256_gcm:
        break;
    default:
        // Invalid type
        return -2;
    }

    AziHsmKeyImport key_data = {
        .wrapped_key = wrapped_key,
        .wrapped_key_len = wrapped_key_len,
        .digest_kind = (unsigned int)digest_kind,
        .key_usage = (unsigned int)AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT,
        .key_availability = (unsigned int)availability,
        .key_name = name,
        .data = (void *)ctx};

    return ENGINE_ctrl(engine, AZIHSM_CMD_IMPORT_EVP_CIPHER_CTX, nid, (void *)&key_data, NULL);
}

/// @brief Unwrap an AES key (XTS context)
/// @param engine Pointer to OpenSSL ENGINE
/// @param ctx EVP_CIPHER_CTX structure to populate with the imported key
/// @param digest_kind Type of digest key is wrapped with
/// @param wrapped_key Blob of wrapped data
/// @param wrapped_key_len Length of blob of wrapped data
/// @param wrapped_key2 Blob of wrapped data (second part of key)
/// @param wrapped_key2_len Length of blob of wrapped data (second part of key)
/// @param name Pointer to key ID (may be NULL if ephemeral)
/// @param availability Availability of key
/// @return 1 on success, 0 on failure
///
/// @note This function must only be used for keys used for XTS operations
static inline int azihsm_unwrap_aes_xts(
    ENGINE *engine,
    EVP_CIPHER_CTX *ctx,
    AziHsmDigestKind digest_kind,
    const unsigned char *wrapped_key,
    size_t wrapped_key_len,
    const unsigned char *wrapped_key2,
    size_t wrapped_key2_len,
    const char *name,
    AziHsmKeyAvailability availability)
{
    AziHsmKeyImport key_data = {
        .wrapped_key = wrapped_key,
        .wrapped_key_len = wrapped_key_len,
        .wrapped_key2 = wrapped_key2,
        .wrapped_key2_len = wrapped_key2_len,
        .digest_kind = (unsigned int)digest_kind,
        .key_usage = (unsigned int)AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT,
        .key_availability = (unsigned int)availability,
        .key_name = name,
        .data = (void *)ctx};

    // Only valid NID for this operation
    return ENGINE_ctrl(engine, AZIHSM_CMD_IMPORT_EVP_CIPHER_CTX, NID_aes_256_xts, (void *)&key_data, NULL);
}

/// @brief Unwrap an RSA key
/// @param engine Pointer to OpenSSL ENGINE
/// @param ctx EVP_PKEY_CTX structure to populate with the imported key
/// @param digest_kind Type of digest key is wrapped with
/// @param wrapped_key Blob of wrapped data
/// @param wrapped_key_len Length of blob of wrapped data
/// @param name Pointer to key ID (may be NULL if ephemeral)
/// @param availability Availability of key
/// @return 1 on success, 0 on failure
static inline int azihsm_unwrap_evp_pkey_rsa(
    ENGINE *engine,
    EVP_PKEY_CTX *ctx,
    AziHsmDigestKind digest_kind,
    AziHsmKeyUsage key_usage,
    const unsigned char *wrapped_key,
    size_t wrapped_key_len,
    const char *name,
    AziHsmKeyAvailability availability)
{
    AziHsmKeyImport key_data = {
        .wrapped_key = wrapped_key,
        .wrapped_key_len = wrapped_key_len,
        .digest_kind = (unsigned int)digest_kind,
        .key_usage = (unsigned int)key_usage,
        .key_availability = (unsigned int)availability,
        .key_name = name,
        .data = (void *)ctx};

    // NID is not relevant here, key usage derived from struct
    return ENGINE_ctrl(engine, AZIHSM_CMD_IMPORT_EVP_PKEY_CTX_RSA, NID_rsaEncryption, (void *)&key_data, NULL);
}

/// @brief Unwrap an ECC key
/// @param engine Pointer to OpenSSL ENGINE
/// @param ctx EVP_PKEY_CTX structure to populate with the imported key
/// @param curve_name NID of the curve to use
/// @param digest_kind Type of digest key is wrapped with
/// @param wrapped_key Blob of wrapped data
/// @param wrapped_key_len Length of blob of wrapped data
/// @param name Pointer to key ID (may be NULL if ephemeral)
/// @param availability Availability of key
/// @return 1 on success, 0 on failure
static inline int azihsm_unwrap_evp_pkey_ecc(
    ENGINE *engine,
    EVP_PKEY_CTX *ctx,
    int curve_name,
    AziHsmDigestKind digest_kind,
    AziHsmKeyUsage key_usage,
    const unsigned char *wrapped_key,
    size_t wrapped_key_len,
    const char *name,
    AziHsmKeyAvailability availability)
{
    AziHsmKeyImport key_data = {
        .wrapped_key = wrapped_key,
        .wrapped_key_len = wrapped_key_len,
        .digest_kind = (unsigned int)digest_kind,
        .key_usage = (unsigned int)key_usage,
        .key_availability = (unsigned int)availability,
        .key_name = name,
        .data = (void *)ctx};

    return ENGINE_ctrl(engine, AZIHSM_CMD_IMPORT_EVP_PKEY_CTX_ECC, curve_name, (void *)&key_data, NULL);
}

/// @brief Unwrap an ECC key into an EC_KEY
/// @param engine Pointer to OpenSSL ENGINE
/// @param key EC_KEY structure to populate with the imported key
/// @param digest_kind Type of digest key is wrapped with
/// @param wrapped_key Blob of wrapped data
/// @param wrapped_key_len Length of blob of wrapped data
/// @param name Pointer to key ID (may be NULL if ephemeral)
/// @param availability Availability of key
/// @return 1 on success, 0 on failure
static inline int azihsm_unwrap_ecc(
    ENGINE *engine,
    EC_KEY *key,
    AziHsmDigestKind digest_kind,
    AziHsmKeyUsage key_usage,
    const unsigned char *wrapped_key,
    size_t wrapped_key_len,
    const char *name,
    AziHsmKeyAvailability availability)
{
    AziHsmKeyImport key_data = {
        .wrapped_key = wrapped_key,
        .wrapped_key_len = wrapped_key_len,
        .digest_kind = (unsigned int)digest_kind,
        .key_usage = (unsigned int)key_usage,
        .key_availability = (unsigned int)availability,
        .key_name = name,
        .data = (void *)key};

    // NID isn't important as long as it's one of the valid ones for ECC (key type is detected)
    return ENGINE_ctrl(engine, AZIHSM_CMD_IMPORT_EC_KEY, NID_secp384r1, (void *)&key_data, NULL);
}

/// @brief Unwrap an RSA key
/// @param engine Pointer to OpenSSL ENGINE
/// @param ctx RSA structure to populate with the imported key
/// @param digest_kind Type of digest key is wrapped with
/// @param wrapped_key Blob of wrapped data
/// @param wrapped_key_len Length of blob of wrapped data
/// @param name Pointer to key ID (may be NULL if ephemeral)
/// @param availability Availability of key
/// @return 1 on success, 0 on failure
static inline int azihsm_unwrap_rsa(
    ENGINE *engine,
    RSA *key,
    AziHsmDigestKind digest_kind,
    AziHsmKeyUsage key_usage,
    const unsigned char *wrapped_key,
    size_t wrapped_key_len,
    const char *name,
    AziHsmKeyAvailability availability)
{
    AziHsmKeyImport key_data = {
        .wrapped_key = wrapped_key,
        .wrapped_key_len = wrapped_key_len,
        .digest_kind = (unsigned int)digest_kind,
        .key_usage = (unsigned int)key_usage,
        .key_availability = (unsigned int)availability,
        .key_name = name,
        .data = (void *)key};

    // NID is not relevant here, key usage derived from struct
    return ENGINE_ctrl(engine, AZIHSM_CMD_IMPORT_RSA, NID_rsaEncryption, (void *)&key_data, NULL);
}

/// @brief Attest a key
/// @param engine Pointer to OpenSSL ENGINE
/// @param cmd Key attest command to execute
/// @param key Key to attest
/// @param report_data Report data
/// @param report_data_len Length of report data
/// @param claim Claim data
/// @param claim_len Length of claim data
/// @return 1 on success, 0 on failure
static inline int azihsm_attest_key(
    ENGINE *engine,
    AziHsmEngineCommand cmd,
    unsigned char *key,
    unsigned char *report_data,
    size_t report_data_len,
    unsigned char *claim,
    size_t *claim_len)
{
    if (claim_len == NULL)
        return 0;

    switch (cmd)
    {
    case AZIHSM_CMD_ATTEST_EC_KEY:
    case AZIHSM_CMD_ATTEST_RSA:
    case AZIHSM_CMD_ATTEST_EVP_PKEY_RSA:
    case AZIHSM_CMD_ATTEST_EVP_PKEY_ECC:
    case AZIHSM_CMD_ATTEST_BUILTIN_UNWRAP_KEY:
    {
        AziHsmAttestKey attest_data = {
            .key = (unsigned char *)key,
            .report_data = report_data,
            .report_data_len = report_data_len,
            .claim = claim,
            .claim_len = *claim_len};

        int ret = ENGINE_ctrl(engine, cmd, 0, (void *)&attest_data, NULL);
        if (ret == 1)
            *claim_len = attest_data.claim_len;
        return ret;
    }
    default:
        return 0;
    }
}

/// @brief Attest Built-in unwrapping key
/// When called with NULL for the claim, the function will return the length of the claim data
/// @param engine Pointer to OpenSSL ENGINE
/// @param report_data Report data
/// @param report_data_len Length of report data
/// @param claim Claim data
/// @param claim_len Length of claim data
/// @return 1 on success, 0 on failure
static inline int azihsm_attest_builtin_unwrap_key(
    ENGINE *engine,
    unsigned char *report_data,
    size_t report_data_len,
    unsigned char *claim,
    size_t *claim_len)
{
    return azihsm_attest_key(engine, AZIHSM_CMD_ATTEST_BUILTIN_UNWRAP_KEY, NULL, report_data, report_data_len, claim, claim_len);
}

/// @brief Attest an RSA key in RSA structure format
/// When called with NULL for the claim, the function will return the length of the claim data
/// @param engine Pointer to OpenSSL ENGINE
/// @param key RSA key to attest
/// @param report_data Report data
/// @param claim Claim data
/// @param claim_len Length of claim data
/// @return 1 on success, 0 on failure
static inline int azihsm_attest_rsa(
    ENGINE *engine,
    RSA *key,
    unsigned char *report_data,
    size_t report_data_len,
    unsigned char *claim,
    size_t *claim_len)
{
    return azihsm_attest_key(engine, AZIHSM_CMD_ATTEST_RSA, (unsigned char *)key, report_data, report_data_len, claim, claim_len);
}

/// @brief Attest an EC Key in EC_KEY format
/// When called with NULL for the claim, the function will return the length of the claim data
/// @param engine Pointer to OpenSSL ENGINE
/// @param key EC_KEY to attest
/// @param report_data Report data
/// @param claim Claim data
/// @param claim_len Length of claim data
/// @return 1 on success, 0 on failure
static inline int azihsm_attest_ecc(
    ENGINE *engine,
    EC_KEY *key,
    unsigned char *report_data,
    size_t report_data_len,
    unsigned char *claim,
    size_t *claim_len)
{
    return azihsm_attest_key(engine, AZIHSM_CMD_ATTEST_EC_KEY, (unsigned char *)key, report_data, report_data_len, claim, claim_len);
}

/// @brief Attest an RSA key in EVP_PKEY format
/// When called with NULL for the claim, the function will return the length of the claim data
/// @param engine Pointer to OpenSSL ENGINE
/// @param key EVP_PKEY to attest
/// @param report_data Report data
/// @param report_data_len Length of report data
/// @param claim Claim data
/// @param claim_len Length of claim data
/// @return 1 on success, 0 on failure
static inline int azihsm_attest_evp_pkey_rsa(
    ENGINE *engine,
    EVP_PKEY *key,
    unsigned char *report_data,
    size_t report_data_len,
    unsigned char *claim,
    size_t *claim_len)
{
    return azihsm_attest_key(engine, AZIHSM_CMD_ATTEST_EVP_PKEY_RSA, (unsigned char *)key, report_data, report_data_len, claim, claim_len);
}

/// @brief Attest an EC key in EVP_PKEY format
/// When called with NULL for the claim, the function will return the length of the claim data
/// @param engine Pointer to OpenSSL ENGINE
/// @param key EVP_PKEY to attest
/// @param report_data Report data
/// @param report_data_len Length of report data
/// @param claim Claim data
/// @param claim_len Length of claim data
/// @return 1 on success, 0 on failure
static inline int azihsm_attest_evp_pkey_ecc(
    ENGINE *engine,
    EVP_PKEY *key,
    unsigned char *report_data,
    size_t report_data_len,
    unsigned char *claim,
    size_t *claim_len)
{
    return azihsm_attest_key(engine, AZIHSM_CMD_ATTEST_EVP_PKEY_ECC, (unsigned char *)key, report_data, report_data_len, claim, claim_len);
}

/// @brief Get the AZIHSM device collateral (device certificate chain)
/// When called with NULL for the collateral, the function will return the length of the collateral data
/// @param engine Pointer to OpenSSL ENGINE
/// @param collateral Collateral data
/// @param collateral_len Length of collateral data
/// @return 1 on success, 0 on failure
static inline int azihsm_get_collateral(
    ENGINE *engine,
    unsigned char *collateral,
    size_t *collateral_len)
{
    AziHsmCollateral collateral_data = {
        .collateral = collateral,
        .collateral_len = *collateral_len};

    int ret = ENGINE_ctrl(engine, AZIHSM_CMD_GET_COLLATERAL, 0, (void *)&collateral_data, NULL);
    if (ret == 1)
        *collateral_len = collateral_data.collateral_len;
    return ret;
}

/// @brief Delete a key by name
/// @param engine Pointer to OpenSSL ENGINE
/// @param name Name of key to delete
/// @return 1 on success, 0 on failure
///
/// @note Deleting a key in use will invalidate the existing key.
static inline int azihsm_delete_key(ENGINE *engine, const char *name)
{
    return ENGINE_ctrl(engine, AZIHSM_CMD_DELETE_KEY, 0, (void *)name, NULL);
}

#endif // AZIHSM_API_INTERFACE_H
