/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 */

#ifndef AZIHSM_API_H
#define AZIHSM_API_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/*
 Size of AES-GCM IV in bytes.
 */
#define AZIHSM_AES_GCM_IV_SIZE 12

/*
 Size of AES-GCM tag in bytes.
 */
#define AZIHSM_AES_GCM_TAG_SIZE 16

/*
 Length, in bytes, of a partition PSK (Pre-Shared Key). This module is
 shared with the native crate (which does not depend on the wire-types
 crate), so the value is a literal here and pinned to the wire-schema
 `PSK_LEN` by a static assert in the DDI layer.
 */
#define AZIHSM_PSK_LEN 32

enum azihsm_status
#ifdef __cplusplus
    : int32_t
#endif // __cplusplus
{
    AZIHSM_STATUS_SUCCESS = 0,
    AZIHSM_STATUS_INVALID_ARGUMENT = -1,
    AZIHSM_STATUS_INVALID_HANDLE = -2,
    AZIHSM_STATUS_INDEX_OUT_OF_RANGE = -3,
    AZIHSM_STATUS_BUFFER_TOO_SMALL = -4,
    AZIHSM_STATUS_INTERNAL_ERROR = -5,
    AZIHSM_STATUS_RNG_ERROR = -6,
    AZIHSM_STATUS_INVALID_KEY_SIZE = -7,
    AZIHSM_STATUS_DDI_CMD_FAILURE = -8,
    AZIHSM_STATUS_PROPERTY_NOT_PRESENT = -9,
    AZIHSM_STATUS_KEY_CLASS_NOT_SPECIFIED = -10,
    AZIHSM_STATUS_KEY_KIND_NOT_SPECIFIED = -11,
    AZIHSM_STATUS_INVALID_KEY = -12,
    AZIHSM_STATUS_UNSUPPORTED_KEY_KIND = -13,
    AZIHSM_STATUS_UNSUPPORTED_ALGORITHM = -14,
    AZIHSM_STATUS_INVALID_SIGNATURE = -15,
    AZIHSM_STATUS_INVALID_KEY_PROPS = -16,
    AZIHSM_STATUS_UNSUPPORTED_PROPERTY = -17,
    AZIHSM_STATUS_CERT_CHAIN_CHANGED = -18,
    AZIHSM_STATUS_INVALID_TWEAK = -19,
    AZIHSM_STATUS_NOT_FOUND = -20,
    AZIHSM_STATUS_IO_ABORTED = -21,
    AZIHSM_STATUS_IO_ABORT_IN_PROGRESS = -22,
    AZIHSM_STATUS_CREDENTIALS_NOT_ESTABLISHED = -23,
    AZIHSM_STATUS_NONCE_MISMATCH = -24,
    AZIHSM_STATUS_PARTITION_NOT_PROVISIONED = -25,
    AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED = -26,
    AZIHSM_STATUS_ECC_VERIFY_FAILED = -27,
    AZIHSM_STATUS_SESSION_NEEDS_RENEGOTIATION = -29,
    AZIHSM_STATUS_PENDING_KEY_GENERATION = -30,
    AZIHSM_STATUS_KEY_NOT_FOUND = -31,
    AZIHSM_STATUS_PARTITION_ALREADY_PROVISIONED = -33,
    AZIHSM_STATUS_VAULT_APP_LIMIT_REACHED = -34,
    AZIHSM_STATUS_RETRY_EXHAUSTED = -35,
    AZIHSM_STATUS_DEVICE_NOT_READY = -36,
    AZIHSM_STATUS_CANNOT_DELETE_INTERNAL_KEYS = -37,
    AZIHSM_STATUS_UNSUPPORTED_API_REVISION = -38,
    AZIHSM_STATUS_DEVICE_NOT_ACCESSIBLE = -39,
    AZIHSM_STATUS_INVALID_CONTEXT_STATE = -40,
    AZIHSM_STATUS_BK3_ALREADY_INITIALIZED = -41,
    AZIHSM_STATUS_INVALID_SESSION = -42,
    AZIHSM_STATUS_SD_ALREADY_INITIALIZED = -43,
    AZIHSM_STATUS_SD_PEER_CLONING_NOT_ALLOWED = -44,
    AZIHSM_STATUS_UNSUPPORTED_KEY_OPERATION = -45,
    AZIHSM_STATUS_CRYPTO_NOT_INITIALIZED = -46,
    AZIHSM_STATUS_CRYPTO_BUFFER_TOO_SMALL = -47,
    AZIHSM_STATUS_CRYPTO_INPUT_TOO_LARGE = -48,
    AZIHSM_STATUS_CRYPTO_INVALID_ALG = -49,
    AZIHSM_STATUS_CRYPTO_TIMEOUT = -50,
    AZIHSM_STATUS_CRYPTO_UNALIGNED_CPTR = -51,
    AZIHSM_STATUS_CRYPTO_INVALID_ARG = -52,
    AZIHSM_STATUS_CRYPTO_INVALID_IV_LENGTH = -53,
    AZIHSM_STATUS_CRYPTO_INVALID_KEY_LENGTH = -54,
    AZIHSM_STATUS_CRYPTO_INVALID_DATA_LENGTH = -55,
    AZIHSM_STATUS_CRYPTO_INVALID_CONTEXT_LENGTH = -56,
    AZIHSM_STATUS_CRYPTO_INVALID_PARTIAL_CONTEXT = -57,
    AZIHSM_STATUS_CRYPTO_UNSUPPORTED_MODE = -58,
    AZIHSM_STATUS_CRYPTO_UNALIGNED_BUFFER = -59,
    AZIHSM_STATUS_CRYPTO_NOT_SUPPORTED = -60,
    AZIHSM_STATUS_CRYPTO_HARDWARE_ERROR = -61,
    AZIHSM_STATUS_CRYPTO_CPT_RSA_UC_ERR_MOD_LEN_INVALID = -62,
    AZIHSM_STATUS_CRYPTO_CPT_RSA_UC_ERR_EXP_LEN_INVALID = -63,
    AZIHSM_STATUS_CRYPTO_CPT_RSA_UC_ERR_DATA_LEN_INVALID = -64,
    AZIHSM_STATUS_CRYPTO_CPT_GC_UC_ERR_DATA_LEN_INVALID = -65,
    AZIHSM_STATUS_CRYPTO_CPT_GC_UC_ERR_CIPHER_UNSUPPORTED = -66,
    AZIHSM_STATUS_CRYPTO_CPT_GC_UC_ERR_AUTH_UNSUPPORTED = -67,
    AZIHSM_STATUS_CRYPTO_CPT_GC_UC_ERR_HASH_MODE_UNSUPPORTED = -68,
    AZIHSM_STATUS_CRYPTO_CPT_GC_UC_ERR_ICV_MISCOMPARE = -69,
    AZIHSM_STATUS_CRYPTO_CPT_GC_UC_ERR_KEY_LEN_INVALID = -70,
    AZIHSM_STATUS_CRYPTO_CPT_RSA_UC_ERR_PKCS_DECODING = -71,
    AZIHSM_STATUS_CRYPTO_CPT_RSA_UC_ERR_PKCS_SIGNATURE_INVALID = -72,
    AZIHSM_STATUS_CRYPTO_CPT_FAULT = -73,
    AZIHSM_STATUS_CRYPTO_CPT_SW_ERR = -74,
    AZIHSM_STATUS_CRYPTO_CPT_HW_ERR = -75,
    AZIHSM_STATUS_CRYPTO_CPT_INST_ERR = -76,
    AZIHSM_STATUS_CRYPTO_CPT_SW_WARN = -77,
    AZIHSM_STATUS_PANIC = INT32_MIN,
};
#ifndef __cplusplus
typedef int32_t azihsm_status;
#endif // __cplusplus

/*
 HSM Algorithm identifier enumeration.

 This enum defines all supported cryptographic algorithms in the HSM.
 The values are organized by algorithm family:
 - 0x0000xxxx: Masking algorithms
 - 0x0001xxxx: RSA algorithms
 - 0x0002xxxx: Elliptic Curve algorithms
 - 0x0003xxxx: AES algorithms
 - 0x0004xxxx: Hash algorithms (SHA family)
 - 0x0005xxxx: HMAC algorithms
 - 0x0006xxxx: Key Derivation Function algorithms

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum azihsm_algo_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Masking key generation algorithm.
     */
    AZIHSM_ALGO_ID_MASKING_KEY_GEN = 1,
    /*
     Masking key wrap algorithm.
     */
    AZIHSM_ALGO_ID_MASKING_KEYWRAP = 2,
    /*
     RSA Key Unwrap Key Pair Generation.
     */
    AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN = 65537,
    /*
     RSA PKCS#1 v1.5 SHA-1 Sign & Verify.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_SHA1 = 65539,
    /*
     RSA PKCS#1 v1.5 SHA-256 Sign & Verify.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_SHA256 = 65540,
    /*
     RSA PKCS#1 v1.5 SHA-384 Sign & Verify.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_SHA384 = 65541,
    /*
     RSA PKCS#1 v1.5 SHA-512 Sign & Verify.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_SHA512 = 65542,
    /*
     RSA PKCS#1 PSS Sign & Verify.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_PSS = 65543,
    /*
     RSA PKCS#1 PSS SHA-1 Sign & Verify.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA1 = 65544,
    /*
     RSA PKCS#1 PSS SHA-256 Sign & Verify.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA256 = 65545,
    /*
     RSA PKCS#1 PSS SHA-384 Sign & Verify.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA384 = 65546,
    /*
     RSA PKCS#1 PSS SHA-512 Sign & Verify.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA512 = 65547,
    /*
     RSA PKCS#1 OAEP Encrypt & Decrypt.
     */
    AZIHSM_ALGO_ID_RSA_PKCS_OAEP = 65548,
    /*
     RSA PKCS#1  Encrypt & Decrypt.
     */
    AZIHSM_ALGO_ID_RSA_PKCS = 65549,
    /*
     RSA AES Key Wrap & Unwrap.
     */
    AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP = 65550,
    /*
     RSA AES Wrap.
     */
    AZIHSM_ALGO_ID_RSA_AES_WRAP = 65551,
    /*
     EC Key Pair Generation.
     */
    AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN = 131073,
    /*
     ECDSA Sign & Verify.
     */
    AZIHSM_ALGO_ID_ECDSA = 131074,
    /*
     ECDSA SHA-1 Sign & Verify.
     */
    AZIHSM_ALGO_ID_ECDSA_SHA1 = 131075,
    /*
     ECDSA SHA-256 Sign & Verify.
     */
    AZIHSM_ALGO_ID_ECDSA_SHA256 = 131076,
    /*
     ECDSA SHA-384 Sign & Verify.
     */
    AZIHSM_ALGO_ID_ECDSA_SHA384 = 131077,
    /*
     ECDSA SHA-512 Sign & Verify.
     */
    AZIHSM_ALGO_ID_ECDSA_SHA512 = 131078,
    /*
     ECDH Derive.
     */
    AZIHSM_ALGO_ID_ECDH = 131079,
    /*
     AES Key Generation.
     */
    AZIHSM_ALGO_ID_AES_KEY_GEN = 196609,
    /*
     AES CBC Encrypt & Decrypt.
     */
    AZIHSM_ALGO_ID_AES_CBC = 196610,
    /*
     AES CBC Pad Encrypt & Decrypt.
     */
    AZIHSM_ALGO_ID_AES_CBC_PAD = 196611,
    /*
     AES XTS Key Generation.
     */
    AZIHSM_ALGO_ID_AES_XTS_KEY_GEN = 196612,
    /*
     AES XTS Encrypt & Decrypt.
     */
    AZIHSM_ALGO_ID_AES_XTS = 196613,
    /*
     AES GCM Key Generation.
     */
    AZIHSM_ALGO_ID_AES_GCM_KEY_GEN = 196614,
    /*
     AES GCM Encrypt & Decrypt.
     */
    AZIHSM_ALGO_ID_AES_GCM = 196615,
    /*
     SHA-1 Digest.
     */
    AZIHSM_ALGO_ID_SHA1 = 262145,
    /*
     SHA-256 Digest.
     */
    AZIHSM_ALGO_ID_SHA256 = 262146,
    /*
     SHA-384 Digest.
     */
    AZIHSM_ALGO_ID_SHA384 = 262147,
    /*
     SHA-512 Digest.
     */
    AZIHSM_ALGO_ID_SHA512 = 262148,
    /*
     HMAC SHA-1 Sign & Verify.
     */
    AZIHSM_ALGO_ID_HMAC_SHA1 = 327681,
    /*
     HMAC SHA-256 Sign & Verify.
     */
    AZIHSM_ALGO_ID_HMAC_SHA256 = 327682,
    /*
     HMAC SHA-384 Sign & Verify.
     */
    AZIHSM_ALGO_ID_HMAC_SHA384 = 327683,
    /*
     HMAC SHA-512 Sign & Verify.
     */
    AZIHSM_ALGO_ID_HMAC_SHA512 = 327684,
    /*
     HKDF Derive.
     */
    AZIHSM_ALGO_ID_HKDF_DERIVE = 393217,
    /*
     SP 800-108 KDF Counter Derive.
     */
    AZIHSM_ALGO_ID_KBKDF_COUNTER_DERIVE = 393218,
    /*
     Security-domain sealing key generation.
     */
    AZIHSM_ALGO_ID_SD_SEALING_KEY_GEN = 458753,
};
#ifndef __cplusplus
typedef uint32_t azihsm_algo_id;
#endif // __cplusplus

/*
 Key property identifier enumeration.

 This enum defines the various properties that can be associated with cryptographic keys
 in the HSM. Each property has a unique identifier that is used to query or set specific
 attributes of a key object.

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum azihsm_key_prop_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Key class property (e.g., Private, Public, Secret).
     */
    AZIHSM_KEY_PROP_ID_CLASS = 1,
    /*
     Key kind property (e.g., RSA, ECC, AES).
     */
    AZIHSM_KEY_PROP_ID_KIND = 2,
    /*
     Bit length of the key.
     */
    AZIHSM_KEY_PROP_ID_BIT_LEN = 3,
    /*
     Human-readable label for the key.
     */
    AZIHSM_KEY_PROP_ID_LABEL = 4,
    /*
     Public key information associated with the key.
     */
    AZIHSM_KEY_PROP_ID_PUB_KEY_INFO = 5,
    /*
     Elliptic curve identifier for ECC keys.
     */
    AZIHSM_KEY_PROP_ID_EC_CURVE = 6,
    /*
     Whether the key is masked (protected by hardware).
     */
    AZIHSM_KEY_PROP_ID_MASKED_KEY = 7,
    /*
     Session handle associated with the key.
     */
    AZIHSM_KEY_PROP_ID_SESSION = 8,
    /*
     Whether the key was generated locally in the HSM.
     */
    AZIHSM_KEY_PROP_ID_LOCAL = 9,
    /*
     Whether the key is sensitive (cannot be revealed in plaintext).
     */
    AZIHSM_KEY_PROP_ID_SENSITIVE = 10,
    /*
     Whether the key can be extracted from the HSM.
     */
    AZIHSM_KEY_PROP_ID_EXTRACTABLE = 11,
    /*
     Whether the key can be used for encryption operations.
     */
    AZIHSM_KEY_PROP_ID_ENCRYPT = 12,
    /*
     Whether the key can be used for decryption operations.
     */
    AZIHSM_KEY_PROP_ID_DECRYPT = 13,
    /*
     Whether the key can be used for signing operations.
     */
    AZIHSM_KEY_PROP_ID_SIGN = 14,
    /*
     Whether the key can be used for verification operations.
     */
    AZIHSM_KEY_PROP_ID_VERIFY = 15,
    /*
     Whether the key can be used for key wrapping operations.
     */
    AZIHSM_KEY_PROP_ID_WRAP = 16,
    /*
     Whether the key can be used for key unwrapping operations.
     */
    AZIHSM_KEY_PROP_ID_UNWRAP = 17,
    /*
     Whether the key can be used for key derivation operations.
     */
    AZIHSM_KEY_PROP_ID_DERIVE = 18,
};
#ifndef __cplusplus
typedef uint32_t azihsm_key_prop_id;
#endif // __cplusplus

/*
 Cryptographic key algorithm type.

 Specifies the algorithm family for a cryptographic key.
 */
enum azihsm_key_kind
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     RSA asymmetric key kind.
     */
    AZIHSM_KEY_KIND_RSA = 1,
    /*
     Elliptic Curve (EC) asymmetric key kind.
     */
    AZIHSM_KEY_KIND_ECC = 2,
    /*
     Advanced Encryption Standard (AES) symmetric key kind.
     */
    AZIHSM_KEY_KIND_AES = 3,
    /*
     AES XTS symmetric key kind.
     */
    AZIHSM_KEY_KIND_AES_XTS = 4,
    /*
     Shared secret key kind.
     */
    AZIHSM_KEY_KIND_SHARED_SECRET = 5,
    /*
     HMAC SHA 1 is not supported.
     HMAC SHA 256
     */
    AZIHSM_KEY_KIND_HMAC_SHA256 = 7,
    /*
     HMAC SHA 384
     */
    AZIHSM_KEY_KIND_HMAC_SHA384 = 8,
    /*
     HMAC SHA 512
     */
    AZIHSM_KEY_KIND_HMAC_SHA512 = 9,
    /*
     AES GCM symmetric key kind.
     */
    AZIHSM_KEY_KIND_AES_GCM = 10,
    /*
     HSM Sealing key kind (used for sealing/unsealing operations).
     */
    AZIHSM_KEY_KIND_SEALING = 11,
    /*
     RSA CRT
     */
    AZIHSM_KEY_KIND_RSA_CRT = 12,
};
#ifndef __cplusplus
typedef uint32_t azihsm_key_kind;
#endif // __cplusplus

/*
 Owner backup key source.

 Specifies the source of the owner backup key (OBK) during partition initialization.
 */
enum azihsm_owner_backup_key_source
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Caller provided backup key.
     */
    AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER = 1,
    /*
     TPM-sealed backup key (retrieved from device and unsealed).
     */
    AZIHSM_OWNER_BACKUP_KEY_SOURCE_TPM = 2,
};
#ifndef __cplusplus
typedef uint32_t azihsm_owner_backup_key_source;
#endif // __cplusplus

/*
 HSM partition owner trust anchor (aka POTA) endorsement source.
 */
enum azihsm_pota_endorsement_source
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Caller provided endorsement.
     */
    AZIHSM_POTA_ENDORSEMENT_SOURCE_CALLER = 1,
    /*
     TPM-generated endorsement.
     */
    AZIHSM_POTA_ENDORSEMENT_SOURCE_TPM = 2,
};
#ifndef __cplusplus
typedef uint32_t azihsm_pota_endorsement_source;
#endif // __cplusplus

/*
 Partition property identifier enumeration.

 This enum defines the various properties that can be queried from an HSM partition.
 Each property has a unique identifier that is used to retrieve specific attributes
 of a partition.

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum azihsm_part_prop_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Device type property (Virtual or Physical).
     */
    AZIHSM_PART_PROP_ID_TYPE = 1,
    /*
     OS device path.
     */
    AZIHSM_PART_PROP_ID_PATH = 2,
    /*
     Driver version string.
     */
    AZIHSM_PART_PROP_ID_DRIVER_VERSION = 3,
    /*
     Firmware version string.
     */
    AZIHSM_PART_PROP_ID_FIRMWARE_VERSION = 4,
    /*
     Hardware version string.
     */
    AZIHSM_PART_PROP_ID_HARDWARE_VERSION = 5,
    /*
     PCI hardware ID (bus:device:function).
     */
    AZIHSM_PART_PROP_ID_PCI_HW_ID = 6,
    /*
     Minimum API revision supported by the device.
     */
    AZIHSM_PART_PROP_ID_MIN_API_REV = 7,
    /*
     Maximum API revision supported by the device.
     */
    AZIHSM_PART_PROP_ID_MAX_API_REV = 8,
    /*
     Manufacturer certificate chain in PEM format.
     */
    AZIHSM_PART_PROP_ID_MANUFACTURER_CERT_CHAIN = 9,
    /*
     Backup masking key (BMK).
     */
    AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY = 10,
    /*
     Masked owner backup key (MOBK).
     */
    AZIHSM_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY = 11,
    /*
     Partition identity (PID) public key in DER format.
     */
    AZIHSM_PART_PROP_ID_PART_PUB_KEY = 12,
    /*
     16-byte partition identity (PID).
     */
    AZIHSM_PART_PROP_ID_PART_EX_PID = 13,
    /*
     Raw ECC-P384 partition identity public key (`x ‖ y`, 96 bytes).
     */
    AZIHSM_PART_PROP_ID_PART_EX_PUB_KEY = 14,
};
#ifndef __cplusplus
typedef uint32_t azihsm_part_prop_id;
#endif // __cplusplus

/*
 Channel-level integrity profile for a security-domain (TBOR) session,
 selected by the caller when opening a session via `open_session_ex`.

 API-layer mirror of `azihsm_ddi_tbor_types::SessionType`; kept as a
 separate `#[open_enum]` so the public API surface does not leak the
 DDI-layer wire type.
 */
enum azihsm_session_ex_type
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Channel transports bodies without per-message MAC.
     */
    AZIHSM_SESSION_EX_TYPE_PLAIN_TEXT = 0,
    /*
     Channel transports bodies wrapped in an outer per-message HMAC
     envelope.
     */
    AZIHSM_SESSION_EX_TYPE_AUTHENTICATED = 1,
};
#ifndef __cplusplus
typedef uint32_t azihsm_session_ex_type;
#endif // __cplusplus

/*
 Session property identifier enumeration.

 This enum defines the various properties that can be queried from an HSM session.
 Each property has a unique identifier that is used to retrieve specific attributes
 of a session.

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum azihsm_session_prop_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     API revision used by the session.
     */
    AZIHSM_SESSION_PROP_ID_API_REV = 1,
};
#ifndef __cplusplus
typedef uint32_t azihsm_session_prop_id;
#endif // __cplusplus

/*
 MGF1 (Mask Generation Function 1) identifier enumeration.

 This enum defines the supported mask generation functions used in RSA operations,
 particularly for OAEP padding schemes. MGF1 is based on hash functions and provides
 deterministic mask generation for cryptographic operations.

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum azihsm_mgf1_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     MGF1 with SHA-256 hash function
     */
    AZIHSM_MGF1_ID_SHA256 = 1,
    /*
     MGF1 with SHA-384 hash function
     */
    AZIHSM_MGF1_ID_SHA384 = 2,
    /*
     MGF1 with SHA-512 hash function
     */
    AZIHSM_MGF1_ID_SHA512 = 3,
    /*
     MGF1 with SHA-1 hash function
     */
    AZIHSM_MGF1_ID_SHA1 = 4,
};
#ifndef __cplusplus
typedef uint32_t azihsm_mgf1_id;
#endif // __cplusplus

/*
 Elliptic Curve Cryptography (ECC) curve identifier.

 Specifies the elliptic curve used for ECC keys, as defined by NIST.
 */
enum azihsm_ecc_curve
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     NIST P-256 curve (secp256r1), approximately 128-bit security strength.
     */
    AZIHSM_ECC_CURVE_P256 = 1,
    /*
     NIST P-384 curve (secp384r1), approximately 192-bit security strength.
     */
    AZIHSM_ECC_CURVE_P384 = 2,
    /*
     NIST P-521 curve (secp521r1), approximately 256-bit security strength.
     */
    AZIHSM_ECC_CURVE_P521 = 3,
};
#ifndef __cplusplus
typedef uint32_t azihsm_ecc_curve;
#endif // __cplusplus

/*
 Cryptographic key class.

 Defines the fundamental category of a cryptographic key.
 */
enum azihsm_key_class
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Symmetric secret key (e.g., AES, HMAC).
     */
    AZIHSM_KEY_CLASS_SECRET = 1,
    /*
     Public key from an asymmetric key pair.
     */
    AZIHSM_KEY_CLASS_PUBLIC = 2,
    /*
     Private key from an asymmetric key pair.
     */
    AZIHSM_KEY_CLASS_PRIVATE = 3,
};
#ifndef __cplusplus
typedef uint32_t azihsm_key_class;
#endif // __cplusplus

/*
 HSM partition type.

 Indicates whether the partition is a virtual (simulated) or physical (hardware) device.
 */
enum azihsm_part_type
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Virtual/simulated partition.
     */
    AZIHSM_PART_TYPE_VIRTUAL = 1,
    /*
     Physical hardware partition.
     */
    AZIHSM_PART_TYPE_PHYSICAL = 2,
};
#ifndef __cplusplus
typedef uint32_t azihsm_part_type;
#endif // __cplusplus

/*
 Opaque partition-policy builder handle.

 Created by [`azihsm_part_policy_builder_new`], populated through the
 `azihsm_part_policy_builder_set_*` setters, serialized with
 [`azihsm_part_policy_build`], and released with
 [`azihsm_part_policy_builder_free`].
 */
struct azihsm_part_policy_builder;

/*
 Error type used throughout the native API.

 An alias for `HsmError` that represents all possible error conditions
 in the HSM API. This type is returned across the ABI boundary and can
 be converted to appropriate error codes for C callers.
 */
typedef azihsm_status azihsm_status;

/*
 Handle type for referencing HSM objects across the FFI boundary.

 A 32-bit unsigned integer used as an opaque handle to reference HSM objects
 such as partitions, sessions, and keys. Handles are managed by the global
 handle table and should be treated as opaque identifiers by C callers.
 */
typedef uint32_t azihsm_handle;

/*
 Cryptographic algorithm structure for specifying algorithm parameters.

 This structure is used to specify the algorithm identifier and
 any associated parameters for cryptographic operations in the HSM.

 # Safety
 When using this struct from C code:
 - `params` must point to valid memory for `len` bytes
 - `params` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management

 */
struct azihsm_algo
{
    /*
     Algorithm identifier.
     */
    azihsm_algo_id id;
    /*
     Pointer to algorithm-specific parameters.
     */
    void *params;
    /*
     Length of the algorithm-specific parameters.
     */
    uint32_t len;
};

/*
 Buffer structure for passing data

 # Safety
 When using this struct from C code:
 - `ptr` must point to valid memory for `len` bytes
 - `ptr` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management
 */
struct azihsm_buffer
{
    void *ptr;
    uint32_t len;
};

/*
 Key property

 # Safety
 When using this struct from C code:
 - `val` must point to valid memory for `len` bytes
 - `val` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management

 */
struct azihsm_key_prop
{
    /*
     Property identifier
     */
    azihsm_key_prop_id id;
    /*
     Pointer to the property value
     */
    void *val;
    /*
     Length of the property value in bytes
     */
    uint32_t len;
};

/*
 List of key properties

 # Safety
 When using this struct from C code:
 - `props` must point to valid memory for `count` elements
 - Each element's `val` must point to valid memory for `len` bytes
 - The lifetimes of `props` and its elements must exceed the lifetime of this struct
 - Caller is responsible for proper memory management

 */
struct azihsm_key_prop_list
{
    /*
     Pointer to an array of key properties
     */
    struct azihsm_key_prop *props;
    /*
     Number of key properties in the array
     */
    uint32_t count;
};

/*
 Key kind type used in the native API.

 An alias for `HsmKeyKind` that represents the algorithm type of a cryptographic key.
 This type is used across the FFI boundary to indicate whether a key is RSA, ECC, AES, etc.
 */
typedef azihsm_key_kind azihsm_key_kind;

#if !defined(_WIN32)
/*
 Character (single-byte for non-Windows)
 */
typedef uint8_t azihsm_char;
#endif

#if defined(_WIN32)
/*
 Character (UTF-16 for Windows)
 */
typedef uint16_t azihsm_char;
#endif

/*
 String
 */
struct azihsm_str
{
    /*
     Pointer to the string
     */
    azihsm_char *str;
    /*
     Length of the string (including null terminator)
     */
    uint32_t len;
};

/*
 API revision structure used to specify the desired API version.

 This structure allows clients to specify the major and minor version
 numbers of the API they wish to use. It is used to ensure compatibility
 between different versions of the HSM API.

 */
struct azihsm_api_rev
{
    /*
     Major version number
     */
    uint32_t major;
    /*
     Minor version number
     */
    uint32_t minor;
};

/*
 FFI-safe partition info structure.

 C-compatible representation of `HsmPartitionInfo` with the path
 expressed as an `AzihsmStr` (pointer + length) instead of a Rust `String`,
 and the supported API revision range as min/max fields.
 */
struct azihsm_part_info
{
    /*
     Device path (caller-owned buffer, filled by the API)
     */
    struct azihsm_str path;
    /*
     Minimum supported API revision
     */
    struct azihsm_api_rev api_rev_min;
    /*
     Maximum supported API revision
     */
    struct azihsm_api_rev api_rev_max;
};

/*
 credentials structure used for authentication.

 This structure contains the identifier and PIN required
 to authenticate with the HSM.

 */
struct azihsm_credentials
{
    /*
     Identifier (16 bytes)
     */
    uint8_t id[16];
    /*
     PIN (16 bytes)
     */
    uint8_t pin[16];
};

/*
 Owner backup key source used in the native API.
 An alias for `HsmOwnerBackupKeySource` that represents the source of the owner backup key
 (caller-provided or TPM-sealed).
 */
typedef azihsm_owner_backup_key_source azihsm_owner_backup_key_source;

struct azihsm_owner_backup_key_config
{
    /*
     Source of the owner backup key
     */
    azihsm_owner_backup_key_source source;
    /*
     Pointer to the plaintext owner backup key buffer (OBK).
     Required when `source` is `Caller` and `masked_owner_backup_key`
     is NULL. The device's `init_bk3` operation is one-shot per
     power cycle, so callers should provide OBK only on the first
     init and cache the resulting MOBK (read via the
     `MaskedOwnerBackupKey` property) for subsequent inits.
     */
    const struct azihsm_buffer *owner_backup_key;
    /*
     Pointer to the masked owner backup key buffer (MOBK).
     When non-NULL on a `Caller` source, the SDK skips the OBK→MOBK
     derivation and uses this MOBK directly. Exactly one of
     `owner_backup_key` or `masked_owner_backup_key` must be non-NULL
     for the `Caller` source.
     */
    const struct azihsm_buffer *masked_owner_backup_key;
};

/*
 POTA endorsement source used in the native API.
 An alias for `HsmPotaEndorsementSource` that represents the source of the POTA endorsement
 (caller-provided or TPM-generated).
 */
typedef azihsm_pota_endorsement_source azihsm_pota_endorsement_source;

struct azihsm_pota_endorsement_data
{
    /*
     Pointer to the signature buffer
     */
    const struct azihsm_buffer *signature;
    /*
     Pointer to the public key buffer
     */
    const struct azihsm_buffer *public_key;
};

struct azihsm_pota_endorsement
{
    /*
     Source of the POTA endorsement
     */
    azihsm_pota_endorsement_source source;
    /*
     Pointer to the POTA endorsement data (if source is Caller)
     */
    const struct azihsm_pota_endorsement_data *endorsement;
};

/*
 Storage operations for resiliency.

 All three function pointers are required.

 `read`: Reads data for the given key into the output buffer. If the
 output buffer is too small (or null/zero-length), sets `output->len` to
 the required size and returns `AZIHSM_STATUS_BUFFER_TOO_SMALL`. Returns
 `AZIHSM_STATUS_NOT_FOUND` when the key does not exist.

 `write`: Writes data for the given key (create or overwrite).

 `clear`: Deletes data for the given key. No error if key doesn't exist.
 */
struct azihsm_resiliency_storage_ops
{
    azihsm_status (*read)(void *ctx, const char *key, struct azihsm_buffer *value);
    azihsm_status (*write)(void *ctx, const char *key, const struct azihsm_buffer *value);
    azihsm_status (*clear)(void *ctx, const char *key);
};

/*
 Lock operations for cross-process/thread restore coordination.

 Both function pointers are required. The lock is non-reentrant.
 */
struct azihsm_resiliency_lock_ops
{
    azihsm_status (*lock)(void *ctx);
    azihsm_status (*unlock)(void *ctx);
};

/*
 POTA endorsement callback.

 The `endorse` callback re-endorses the device's PID certificate public
 key with the caller's POTA private key. Uses the two-call buffer pattern:
 first call with null/zero output buffers to query sizes, second call to
 fill them.
 */
struct azihsm_pota_callback_ops
{
    azihsm_status (*endorse)(
        void *ctx,
        const struct azihsm_buffer *pota_pub_key_der,
        const struct azihsm_buffer *pid_pub_key_der,
        const struct azihsm_buffer *pid_cert_chain_pem,
        struct azihsm_buffer *signature,
        struct azihsm_buffer *endorsement_pub_key
    );
};

/*
 MOBK provider callback.

 The `get_mobk` callback returns the caller's MOBK (masked owner backup
 key) during resiliency restore, allowing the SDK to re-provision the
 partition without re-running `init_bk3` (which is one-shot per device
 power cycle). Uses the two-call buffer pattern: first call with
 null/zero output buffer to query size, second call to fill it.
 */
struct azihsm_mobk_callback_ops
{
    azihsm_status (*get_mobk)(void *ctx, struct azihsm_buffer *mobk);
};

/*
 Resiliency configuration passed to `azihsm_part_init`.

 - `ctx`: Opaque context pointer passed back to every callback. The SDK
   never dereferences this — the caller owns and manages it. Must remain
   valid until `azihsm_part_close` returns. **Must not** contain or
   reference the same partition handle — see module-level safety docs.
 - `storage_ops` and `lock_ops` are always required (inline).
 - `pota_callback_ops`: Pointer to POTA callback ops. NULL when POTA
   endorsement source is TPM. Must be non-null when source is Caller.
 - `mobk_callback_ops`: Pointer to MOBK callback ops. NULL when OBK
   source is TPM. Must be non-null when source is Caller.
 */
struct azihsm_resiliency_config
{
    void *ctx;
    struct azihsm_resiliency_storage_ops storage_ops;
    struct azihsm_resiliency_lock_ops lock_ops;
    const struct azihsm_pota_callback_ops *pota_callback_ops;
    const struct azihsm_mobk_callback_ops *mobk_callback_ops;
};

/*
 Partition property structure for querying partition attributes.

 # Safety
 When using this struct from C code:
 - `val` must point to valid memory for `len` bytes
 - `val` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management
 */
struct azihsm_part_prop
{
    /*
     Property identifier.
     */
    azihsm_part_prop_id id;
    /*
     Pointer to the property value.
     */
    void *val;
    /*
     Length of the property value in bytes.
     */
    uint32_t len;
};

/*
 One certificate chain in an SD attestation-evidence party: an array of
 `len` `azihsm_buffer`s, each a DER-encoded certificate (root to leaf).
 */
struct azihsm_sd_cert_chain
{
    /*
     Pointer to an array of `len` DER certificate `azihsm_buffer`s.
     */
    const struct azihsm_buffer *certs;
    /*
     Number of certificates in `certs`.
     */
    uint32_t len;
};

/*
 Attestation evidence for one SD-backup party: three certificate chains
 (manufacturer, owner, partition-owner) and a COSE_Sign1 report. The DER
 bytes are borrowed, not copied.
 */
struct azihsm_sd_evidence
{
    /*
     Manufacturer certificate chain.
     */
    struct azihsm_sd_cert_chain mfgr_cert_chain;
    /*
     Owner certificate chain.
     */
    struct azihsm_sd_cert_chain owner_cert_chain;
    /*
     Partition-owner certificate chain.
     */
    struct azihsm_sd_cert_chain part_owner_cert_chain;
    /*
     COSE_Sign1 attestation-report buffer.
     */
    const struct azihsm_buffer *report;
};

/*
 Input buffers for [`azihsm_sd_create_remote_backup`].
 */
struct azihsm_sd_create_remote_backup_params
{
    /*
     Unified partition-policy image (484 B) describing the domain.
     */
    const struct azihsm_buffer *part_policy;
    /*
     Sender's masked SD-sealing key (from `azihsm_key_gen`), exactly
     `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct azihsm_buffer *masked_sealing_key;
    /*
     Receiver attestation evidence.
     */
    const struct azihsm_sd_evidence *receiver_evidence;
};

/*
 Input buffers for [`azihsm_sd_reseal_remote_backup`].
 */
struct azihsm_sd_reseal_remote_backup_params
{
    /*
     Unified partition-policy image (484 B) describing the domain.
     */
    const struct azihsm_buffer *part_policy;
    /*
     Receiver's masked SD-sealing key (from `azihsm_key_gen`) that
     unseals the source backup, exactly `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct azihsm_buffer *masked_sealing_key;
    /*
     Source (sender) attestation evidence.
     */
    const struct azihsm_sd_evidence *src_evidence;
    /*
     Destination (receiver) attestation evidence.
     */
    const struct azihsm_sd_evidence *dest_evidence;
    /*
     Source remote backup to reseal, exactly `POK_REMOTE_BACKUP_LEN`
     (161 B).
     */
    const struct azihsm_buffer *src_remote_backup;
};

/*
 Input buffers for [`azihsm_sd_restore_remote_backup`].
 */
struct azihsm_sd_restore_remote_backup_params
{
    /*
     Unified partition-policy image (484 B) describing the domain.
     */
    const struct azihsm_buffer *part_policy;
    /*
     Receiver's masked SD-sealing key (from `azihsm_key_gen`) that
     unseals the backup, exactly `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct azihsm_buffer *masked_sealing_key;
    /*
     Sender attestation evidence.
     */
    const struct azihsm_sd_evidence *sender_evidence;
    /*
     Remote backup to restore, exactly `POK_REMOTE_BACKUP_LEN` (161 B).
     */
    const struct azihsm_buffer *src_remote_backup;
    /*
     Previous security-domain masking-key backup, exactly
     `SD_MK_BACKUP_LEN` (260 B).
     */
    const struct azihsm_buffer *prev_sd_mk_backup;
};

/*
 Input buffers for [`azihsm_sd_create_peer_backup`].
 */
struct azihsm_sd_create_peer_backup_params
{
    /*
     Unified partition-policy image (484 B) describing the domain.
     */
    const struct azihsm_buffer *part_policy;
    /*
     Sender's masked SD-sealing key (from `azihsm_key_gen`), exactly
     `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct azihsm_buffer *masked_sealing_key;
    /*
     Destination (peer) attestation evidence.
     */
    const struct azihsm_sd_evidence *dst_evidence;
    /*
     Device-local partition-owner-key backup (276 B) from which BKS3 is
     recovered.
     */
    const struct azihsm_buffer *pok_local_backup;
};

/*
 Input buffers for [`azihsm_sd_restore_peer_backup`].
 */
struct azihsm_sd_restore_peer_backup_params
{
    /*
     Unified partition-policy image (484 B) describing the domain.
     */
    const struct azihsm_buffer *part_policy;
    /*
     Receiver's masked SD-sealing key (from `azihsm_key_gen`) that
     unseals the backup, exactly `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct azihsm_buffer *masked_sealing_key;
    /*
     Source (peer) attestation evidence.
     */
    const struct azihsm_sd_evidence *src_evidence;
    /*
     Peer backup to restore, exactly `POK_REMOTE_BACKUP_LEN` (161 B).
     */
    const struct azihsm_buffer *pok_peer_backup;
    /*
     Previous security-domain masking-key backup, exactly
     `SD_MK_BACKUP_LEN` (260 B).
     */
    const struct azihsm_buffer *prev_sd_mk_backup;
};

/*
 Input buffers for [`azihsm_sd_restore_local_backup`].
 */
struct azihsm_sd_restore_local_backup_params
{
    /*
     Device-local partition-owner-key backup to restore, exactly
     `MASKED_SD_LEN` (276 B).
     */
    const struct azihsm_buffer *pok_local_backup;
    /*
     Security-domain masking-key backup, exactly `SD_MK_BACKUP_LEN`
     (260 B).
     */
    const struct azihsm_buffer *sd_mk_backup;
};

/*
 PSK credential for opening a security-domain session.

 Pairs the PSK slot (`psk_id`) with an optional caller-supplied PSK.
 When the `psk` **field** (below) is NULL, the partition **default** PSK
 for the slot is used — required for the first session, before the
 default is rotated via `azihsm_sess_ex_psk_change`. After rotation,
 point the `psk` field at the rotated secret.
 */
struct azihsm_session_psk
{
    /*
     PSK slot: 0 = Crypto Officer, 1 = Crypto User.
     */
    uint8_t psk_id;
    /*
     Optional PSK buffer (exactly `AZIHSM_PSK_LEN` bytes); NULL selects the
     partition default PSK for the slot.
     */
    const struct azihsm_buffer *psk;
};

typedef azihsm_session_ex_type azihsm_session_ex_type;

/*
 Input buffers for [`azihsm_sess_ex_part_init`].

 Groups the security-domain provisioning inputs into a single struct so
 the call site does not pass them as separate arguments. Each field
 points to an `azihsm_buffer`; `sapota_thumbprint` is optional and may
 be NULL to omit it.
 */
struct azihsm_sess_ex_part_init_params
{
    /*
     Unified partition policy image buffer.
     */
    const struct azihsm_buffer *part_policy;
    /*
     Machine seed plaintext buffer.
     */
    const struct azihsm_buffer *mach_seed;
    /*
     POTA public-key thumbprint buffer.
     */
    const struct azihsm_buffer *pota_thumbprint;
    /*
     SATA public-key thumbprint buffer.
     */
    const struct azihsm_buffer *sata_thumbprint;
    /*
     Optional SAPOTA thumbprint buffer; NULL to omit.
     */
    const struct azihsm_buffer *sapota_thumbprint;
};

/*
 Input buffers for [`azihsm_sess_ex_part_final`].

 Groups the security-domain finalization inputs into a single struct so
 the call site does not pass them as separate arguments. `pta_cert_chain`
 points to an array of `pta_cert_chain_len` `azihsm_buffer`s, each holding
 one DER-encoded PTA certificate (root to leaf). `prev_local_mk_backup` is
 optional and may be NULL to omit it.
 */
struct azihsm_sess_ex_part_final_params
{
    /*
     Unified partition policy image buffer, re-supplied for `POTAPubKey`
     recovery; must match the policy given to `part_init`.
     */
    const struct azihsm_buffer *part_policy;
    /*
     Pointer to an array of `pta_cert_chain_len` `azihsm_buffer`s, each a
     DER-encoded PTA certificate (root to leaf).
     */
    const struct azihsm_buffer *pta_cert_chain;
    /*
     Number of certificates in `pta_cert_chain`.
     */
    uint32_t pta_cert_chain_len;
    /*
     Optional previous `local_mk` backup envelope to restore; NULL to omit.
     */
    const struct azihsm_buffer *prev_local_mk_backup;
};

/*
 Session property structure for querying session attributes.

 # Safety
 When using this struct from C code:
 - `val` must point to valid memory for `len` bytes
 - `val` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management
 */
struct azihsm_session_prop
{
    /*
     Property identifier.
     */
    azihsm_session_prop_id id;
    /*
     Pointer to the property value.
     */
    void *val;
    /*
     Length of the property value in bytes.
     */
    uint32_t len;
};

/*
 AES CBC parameters.
 */
struct azihsm_algo_aes_cbc_params
{
    /*
     IV
     */
    uint8_t iv[16];
};

/*
 AES GCM parameters.
 */
struct azihsm_algo_aes_gcm_params
{
    /*
     IV (12 bytes)
     */
    uint8_t iv[AZIHSM_AES_GCM_IV_SIZE];
    /*
     Tag (16 bytes) for decryption; updated after encryption.
     */
    uint8_t tag[AZIHSM_AES_GCM_TAG_SIZE];
    /*
     Optional AAD buffer
     */
    const struct azihsm_buffer *aad;
};

/*
 AES-XTS algorithm parameters.

 This structure defines the parameters required for AES-XTS encryption/decryption,
 including the sector number (tweak) and data unit length.
 */
struct azihsm_algo_aes_xts_params
{
    /*
     Sector number (tweak value) in little-endian byte format.
     This is a 128-bit value that provides additional security by
     varying the encryption for each data unit.
     */
    uint8_t sector_num[16];
    /*
     Data Unit Length in bytes.
     Specifies the size of each data unit to be encrypted/decrypted.
     Must be at least 16 bytes for XTS mode.
     */
    uint32_t data_unit_length;
};

/*
 ECDH parameter structure matching C API
 */
struct azihsm_algo_ecdh_params
{
    const struct azihsm_buffer *pub_key;
};

/*
 HKDF parameter structure matching C API
 */
struct azihsm_algo_hkdf_params
{
    azihsm_algo_id hmac_algo_id;
    const struct azihsm_buffer *salt;
    const struct azihsm_buffer *info;
};

/*
 SP 800-108 Counter Mode KDF parameter structure matching C API
 */
struct azihsm_algo_kbkdf_counter_params
{
    azihsm_algo_id hmac_algo_id;
    const struct azihsm_buffer *label;
    const struct azihsm_buffer *context;
};

/*
 RSA PKCS OAEP encryption/decryption parameters matching C API.

 Defines parameters for OAEP (Optimal Asymmetric Encryption Padding) operations,
 which provide secure probabilistic encryption using a hash function, mask
 generation function (MGF1), and optional label for context binding.
 */
struct azihsm_algo_rsa_pkcs_oaep_params
{
    /*
     Hash algorithm identifier used for OAEP padding
     */
    azihsm_algo_id hash_algo_id;
    /*
     MGF1 mask generation function identifier.
     */
    azihsm_mgf1_id mgf1_hash_algo_id;
    /*
     Optional label for encryption context (can be null)
     */
    const struct azihsm_buffer *label;
};

/*
 RSA-AES key wrapping parameters matching C API.

 Defines parameters for RSA-AES key wrap/unwrap operations, which combine
 RSA encryption with AES key wrapping to securely transport symmetric keys.
 The RSA key encrypts an AES key, which in turn wraps the target key material.
 */
struct azihsm_algo_rsa_aes_key_wrap_params
{
    /*
     AES key size in bits (typically 128, 192, or 256)
     */
    uint32_t aes_key_bits;
    /*
     OAEP parameters for RSA encryption of the AES key
     */
    const struct azihsm_algo_rsa_pkcs_oaep_params *oaep_params;
};

/*
 RSA-AES Wrap algorithm parameters structure matching C API

 This structure specifies the parameters for RSA-AES generic wrapping,
 which combines RSA-OAEP encryption with AES wrapping to securely
 transport data.
 */
struct azihsm_algo_rsa_aes_wrap_params
{
    /*
     AES key bits
     */
    uint32_t aes_key_bits;
    /*
     OAEP parameters
     */
    const struct azihsm_algo_rsa_pkcs_oaep_params *oaep_params;
};

/*
 RSA PKCS PSS signature parameters matching C API.

 Defines parameters for PSS (Probabilistic Signature Scheme) operations,
 which provide probabilistic signature generation using a hash function,
 mask generation function (MGF1), and salt for enhanced security.
 */
struct azihsm_algo_rsa_pkcs_pss_params
{
    /*
     Hash algorithm identifier used for PSS signature
     */
    azihsm_algo_id hash_algo_id;
    /*
     MGF1 mask generation function identifier (typically matches hash_algo_id)
     */
    azihsm_mgf1_id mgf_id;
    /*
     Salt length in bytes (typically matches hash output size)
     */
    uint32_t salt_len;
};

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

/*
 Compute cryptographic digest (hash) of data using the specified algorithm.

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[in] data Pointer to data buffer to be hashed
 @param[out] digest Pointer to digest output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_digest(
    azihsm_handle sess_handle,
    const struct azihsm_algo *algo,
    const struct azihsm_buffer *data,
    struct azihsm_buffer *digest
);

/*
 Initialize a streaming digest operation.

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[out] ctx_handle Pointer to receive the digest context handle

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_digest_init(
    azihsm_handle sess_handle,
    const struct azihsm_algo *algo,
    azihsm_handle *ctx_handle
);

/*
 Update a streaming digest operation with more data.

 @param[in] ctx_handle Handle to the digest context
 @param[in] data Pointer to data buffer to digest

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_digest_update(
    azihsm_handle ctx_handle,
    const struct azihsm_buffer *data
);

/*
 Finish a streaming digest operation and produce the digest.

 @param[in] ctx_handle Handle to the digest context
 @param[out] digest Pointer to digest output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 AZIHSM_STATUS_BUFFER_TOO_SMALL is returned.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_digest_finish(azihsm_handle ctx_handle, struct azihsm_buffer *digest);

/*
 Encrypt data using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the encryption key
 @param[in] plain_text Pointer to plaintext data buffer
 @param[out] cipher_text Pointer to ciphertext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_encrypt(
    struct azihsm_algo *algo,
    azihsm_handle key_handle,
    const struct azihsm_buffer *plain_text,
    struct azihsm_buffer *cipher_text
);

/*
 Decrypt data using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the decryption key
 @param[in] cipher_text Pointer to ciphertext data buffer
 @param[out] plain_text Pointer to plaintext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_decrypt(
    struct azihsm_algo *algo,
    azihsm_handle key_handle,
    const struct azihsm_buffer *cipher_text,
    struct azihsm_buffer *plain_text
);

/*
 Initialize streaming encryption operation.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the encryption key
 @param[out] ctx_handle Pointer to receive the streaming context handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_encrypt_init(
    struct azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx_handle
);

/*
 Update streaming encryption operation with additional plaintext data.

 @param[in] ctx_handle Handle to the streaming encryption context
 @param[in] plain_text Pointer to plaintext data buffer to encrypt
 @param[out] cipher_text Pointer to ciphertext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_BUFFER_TOO_SMALL error.
 Note: Output may be less than input size if buffering occurs (e.g., for block alignment).

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_encrypt_update(
    azihsm_handle ctx_handle,
    const struct azihsm_buffer *plain_text,
    struct azihsm_buffer *cipher_text
);

/*
 Finish streaming encryption operation and retrieve any remaining ciphertext.

 @param[in] ctx_handle Handle to the streaming encryption context
 @param[out] cipher_text Pointer to ciphertext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_encrypt_finish(
    azihsm_handle ctx_handle,
    struct azihsm_buffer *cipher_text
);

/*
 Initialize streaming decryption operation.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the decryption key
 @param[out] ctx_handle Pointer to receive the streaming context handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_decrypt_init(
    struct azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx_handle
);

/*
 Update streaming decryption operation with additional ciphertext data.

 @param[in] ctx_handle Handle to the streaming decryption context
 @param[in] cipher_text Pointer to ciphertext data buffer to decrypt
 @param[out] plain_text Pointer to plaintext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_BUFFER_TOO_SMALL error.
 Note: Output may be less than input size if buffering occurs (e.g., for block alignment).

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_decrypt_update(
    azihsm_handle ctx_handle,
    const struct azihsm_buffer *cipher_text,
    struct azihsm_buffer *plain_text
);

/*
 Finish streaming decryption operation and retrieve any remaining plaintext.

 @param[in] ctx_handle Handle to the streaming decryption context
 @param[out] plain_text Pointer to plaintext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_decrypt_finish(
    azihsm_handle ctx_handle,
    struct azihsm_buffer *plain_text
);

/*
 Sign data using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the signing key
 @param[in] data Pointer to data buffer to be signed
 @param[out] sig Pointer to signature output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_sign(
    struct azihsm_algo *algo,
    azihsm_handle key_handle,
    const struct azihsm_buffer *data,
    struct azihsm_buffer *sig
);

/*
 Verify signature using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the verification key
 @param[in] data Pointer to data buffer that was signed
 @param[in] sig Pointer to signature buffer to verify

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_verify(
    struct azihsm_algo *algo,
    azihsm_handle key_handle,
    const struct azihsm_buffer *data,
    const struct azihsm_buffer *sig
);

/*
 Initialize streaming sign operation.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the signing key
 @param[out] ctx_handle Pointer to receive the streaming context handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_sign_init(
    struct azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx_handle
);

/*
 Update streaming sign operation with additional data.

 @param[in] ctx_handle Handle to the streaming sign context
 @param[in] data Pointer to data buffer to be signed

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_sign_update(azihsm_handle ctx_handle, const struct azihsm_buffer *data);

/*
 Finish streaming sign operation and retrieve signature.

 @param[in] ctx_handle Handle to the streaming sign context
 @param[out] sig Pointer to signature output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_sign_finish(azihsm_handle ctx_handle, struct azihsm_buffer *sig);

/*
 Initialize streaming verify operation.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the verification key
 @param[out] ctx_handle Pointer to receive the streaming context handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_verify_init(
    struct azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx_handle
);

/*
 Update streaming verify operation with additional data.

 @param[in] ctx_handle Handle to the streaming verify context
 @param[in] data Pointer to data buffer that was signed

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_verify_update(
    azihsm_handle ctx_handle,
    const struct azihsm_buffer *data
);

/*
 Finish streaming verify operation and verify signature.

 @param[in] ctx_handle Handle to the streaming verify context
 @param[in] sig Pointer to signature buffer to verify

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_verify_finish(azihsm_handle ctx_handle, const struct azihsm_buffer *sig);

/*
 Frees a context handle and releases associated resources.

 The handle is invalidated and must not be used after this call.

 Callers **must** call this function for every valid context handle once it
 is no longer needed, regardless of whether the associated operation
 completed successfully or encountered an error.

 # Safety

 - The `handle` must be a valid handle previously returned by one of the
   context creation functions.
 - The handle must not have been previously freed.
 - After this call, the handle becomes invalid and must not be used.

 # Returns

 * `AZIHSM_STATUS_SUCCESS` - Handle freed successfully
 * `AZIHSM_STATUS_INVALID_HANDLE` - Invalid or already freed handle
 */
azihsm_status azihsm_free_ctx_handle(azihsm_handle handle);

/*
 Generate a symmetric key

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[in] key_props Pointer to key properties list
 @param[out] key_handle Pointer to store the generated key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_key_gen(
    azihsm_handle sess_handle,
    const struct azihsm_algo *algo,
    const struct azihsm_key_prop_list *key_props,
    azihsm_handle *key_handle
);

/*
 Generate an asymmetric key pair

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[in] priv_key_props Pointer to private key properties list
 @param[in] pub_key_props Pointer to public key properties list
 @param[out] priv_key_handle Pointer to store the generated private key handle
 @param[out] pub_key_handle Pointer to store the generated public key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_key_gen_pair(
    azihsm_handle sess_handle,
    struct azihsm_algo *algo,
    const struct azihsm_key_prop_list *priv_key_props,
    const struct azihsm_key_prop_list *pub_key_props,
    azihsm_handle *priv_key_handle,
    azihsm_handle *pub_key_handle
);

/*
 Delete a key from the HSM

 @param[in] key_handle Handle to the key to delete

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is marked unsafe due to no_mangle.
 */
azihsm_status azihsm_key_delete(azihsm_handle key_handle);

/*
 Derive a key from a base key

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[in] base_key Handle to the base key
 @param[in] key_props Pointer to key properties list for the derived key
 @param[out] key_handle Pointer to store the derived key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_key_derive(
    azihsm_handle sess_handle,
    struct azihsm_algo *algo,
    azihsm_handle base_key,
    const struct azihsm_key_prop_list *key_props,
    azihsm_handle *key_handle
);

/*
 Unwrap a wrapped key using an unwrapping key

 This function unwraps (decrypts) a previously wrapped key using the specified
 unwrapping key and algorithm. The unwrapped key is imported into the HSM with
 the provided key properties.

 @param[in] algo Pointer to algorithm specification for unwrapping
 @param[in] unwrapping_key Handle to the key used to unwrap (decrypt) the wrapped key
 @param[in] wrapped_key Pointer to buffer containing the wrapped key data
 @param[in] key_props Pointer to key properties list for the unwrapped key
 @param[out] key_handle Pointer to store the unwrapped key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_key_unwrap(
    struct azihsm_algo *algo,
    azihsm_handle unwrapping_key,
    struct azihsm_buffer *wrapped_key,
    const struct azihsm_key_prop_list *key_props,
    azihsm_handle *key_handle
);

/*
 Unwrap a wrapped key pair using an unwrapping key

 This function unwraps (decrypts) a previously wrapped key pair using the specified
 unwrapping key and algorithm. The unwrapped key pair is imported into the HSM with
 the provided key properties.

 @param[in] algo Pointer to algorithm specification for unwrapping
 @param[in] unwrapping_key Handle to the key used to unwrap (decrypt) the wrapped key pair
 @param[in] wrapped_key Pointer to buffer containing the wrapped key pair data
 @param[in] priv_key_props Pointer to private key properties list for the unwrapped key
 @param[in] pub_key_props Pointer to public key properties list for the unwrapped key
 @param[out] priv_key_handle Pointer to store the unwrapped private key handle
 @param[out] pub_key_handle Pointer to store the unwrapped public key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_key_unwrap_pair(
    struct azihsm_algo *algo,
    azihsm_handle unwrapping_key,
    const struct azihsm_buffer *wrapped_key,
    const struct azihsm_key_prop_list *priv_key_props,
    const struct azihsm_key_prop_list *pub_key_props,
    azihsm_handle *priv_key_handle,
    azihsm_handle *pub_key_handle
);

/*
 Unmask a masked symmetric key

 This function unmasks a previously masked symmetric key. The masked key contains
 the key material and properties, so no external properties or unwrapping keys
 are needed. The key is imported into the HSM within the provided session.

 @param[in] sess_handle Handle to the HSM session
 @param[in] key_kind The kind of key to unmask (e.g., AES)
 @param[in] masked_key Pointer to buffer containing the masked key data
 @param[out] key_handle Pointer to store the unmasked key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_key_unmask(
    azihsm_handle sess_handle,
    azihsm_key_kind key_kind,
    const struct azihsm_buffer *masked_key,
    azihsm_handle *key_handle
);

/*
 Unmask a masked key pair

 This function unmasks a previously masked key pair. The masked key contains
 the key material and properties, so no external properties or unwrapping keys
 are needed. The key pair is imported into the HSM within the provided session.

 @param[in] sess_handle Handle to the HSM session
 @param[in] key_kind The kind of key pair to unmask (RSA or ECC)
 @param[in] masked_key Pointer to buffer containing the masked key pair data
 @param[out] priv_key_handle Pointer to store the unmasked private key handle
 @param[out] pub_key_handle Pointer to store the unmasked public key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_key_unmask_pair(
    azihsm_handle sess_handle,
    azihsm_key_kind key_kind,
    const struct azihsm_buffer *masked_key,
    azihsm_handle *priv_key_handle,
    azihsm_handle *pub_key_handle
);

/*
 Generate a key attestation report

 This function generates an attestation report for a key.

 @param[in] key_handle Handle to the key to attest
 @param[in] report_data Pointer to buffer containing custom data to include in the report (exactly
 128 bytes)
 @param[out] report Pointer to buffer to receive the attestation report

 @return 0 on success, or a negative error code on failure

 # Notes
 - The function performs a two-pass operation: first to determine the required buffer
   size, then to generate the actual report
 - The report buffer's length field will be updated with the actual report size

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_generate_key_report(
    azihsm_handle key_handle,
    const struct azihsm_buffer *report_data,
    struct azihsm_buffer *report
);

/*
 Get a property of a key

 @param[in] key Handle to the key
 @param[in/out] key_prop Pointer to key property structure. On input, specifies which property to
 get. On output, contains the property value.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_key_get_prop(azihsm_handle key_handle, struct azihsm_key_prop *key_prop);

/*
 @brief Allocate a new partition-policy builder

 On success, writes a handle to `*out_builder` whose policy starts from
 a version defaulting to `major = 1, minor = 0` with every other field
 zeroed; set the required POTA and SATA keys and any optional fields
 through the `azihsm_part_policy_builder_set_*` functions, then serialize
 it with `azihsm_part_policy_build`. Release it with
 `azihsm_part_policy_builder_free`.

 A key / `info` / backing-id that does not satisfy its field's length
 requirement is rejected at `azihsm_part_policy_build` time (returning
 `AZIHSM_STATUS_INVALID_ARGUMENT`) rather than silently truncated or
 padded.
 Missing either POTA or SATA key also causes `azihsm_part_policy_build`
 to return `AZIHSM_STATUS_INVALID_ARGUMENT`.
 Unsupported major versions and reserved flag bits are rejected at
 build time as well.

 @param[out] out_builder Receives the non-NULL builder handle on
             success; left unmodified on failure.

 @return `AZIHSM_STATUS_SUCCESS` on success, or
         `AZIHSM_STATUS_INVALID_ARGUMENT` if `out_builder` is NULL.

 # Safety

 - `out_builder` must be a valid, writable pointer to storage for one
   `azihsm_part_policy_builder *`.
 */
azihsm_status azihsm_part_policy_builder_new(struct azihsm_part_policy_builder **out_builder);

/*
 @brief Free a partition-policy builder

 Releases a handle returned by `azihsm_part_policy_builder_new`.
 Passing NULL is a no-op. The handle must not be used afterwards.

 @param[in] builder Builder handle to free (may be NULL)

 # Safety

 - `builder` must be NULL or a handle returned by
   `azihsm_part_policy_builder_new` that has not already been freed.
 */
void azihsm_part_policy_builder_free(struct azihsm_part_policy_builder *builder);

/*
 @brief Set the policy version (`major.minor`)

 Major version must be 1; any minor version is accepted. An unsupported
 major version is rejected at `azihsm_part_policy_build` time.

 @param[in] builder Builder handle
 @param[in] major Major version number
 @param[in] minor Minor version number
 @return `AZIHSM_STATUS_SUCCESS`, or `AZIHSM_STATUS_INVALID_ARGUMENT` on a NULL handle

 # Safety

 - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
 */
azihsm_status azihsm_part_policy_builder_set_version(
    struct azihsm_part_policy_builder *builder,
    uint8_t major,
    uint8_t minor
);

/*
 @brief Set the POTA (Partition Owner Trust Anchor) public key

 @param[in] builder Builder handle
 @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
 @param[in] key Raw public-key bytes
 @return `AZIHSM_STATUS_SUCCESS`, or `AZIHSM_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
 */
azihsm_status azihsm_part_policy_builder_set_pota_key(
    struct azihsm_part_policy_builder *builder,
    uint16_t kind,
    const struct azihsm_buffer *key
);

/*
 @brief Set the SATA (Sealing Authority Trust Anchor) public key

 @param[in] builder Builder handle
 @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
 @param[in] key Raw public-key bytes
 @return `AZIHSM_STATUS_SUCCESS`, or `AZIHSM_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
 */
azihsm_status azihsm_part_policy_builder_set_sata_key(
    struct azihsm_part_policy_builder *builder,
    uint16_t kind,
    const struct azihsm_buffer *key
);

/*
 @brief Set the SAPOTA (Sealing Authority's POTA) public key

 @param[in] builder Builder handle
 @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
 @param[in] key Raw public-key bytes
 @return `AZIHSM_STATUS_SUCCESS`, or `AZIHSM_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
 */
azihsm_status azihsm_part_policy_builder_set_sapota_key(
    struct azihsm_part_policy_builder *builder,
    uint16_t kind,
    const struct azihsm_buffer *key
);

/*
 @brief Set the backing-partition identifier

 @param[in] builder Builder handle
 @param[in] id Backing-partition identifier bytes
 @return `AZIHSM_STATUS_SUCCESS`, or `AZIHSM_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
 */
azihsm_status azihsm_part_policy_builder_set_backup_part_id(
    struct azihsm_part_policy_builder *builder,
    const struct azihsm_buffer *id
);

/*
 @brief Set the backing-partition public key

 @param[in] builder Builder handle
 @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
 @param[in] key Raw public-key bytes
 @return `AZIHSM_STATUS_SUCCESS`, or `AZIHSM_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
 */
azihsm_status azihsm_part_policy_builder_set_backup_part_pub_key(
    struct azihsm_part_policy_builder *builder,
    uint16_t kind,
    const struct azihsm_buffer *key
);

/*
 @brief Set the caller-provided opaque `info` field

 @param[in] builder Builder handle
 @param[in] info Opaque info bytes
 @return `AZIHSM_STATUS_SUCCESS`, or `AZIHSM_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
 */
azihsm_status azihsm_part_policy_builder_set_info(
    struct azihsm_part_policy_builder *builder,
    const struct azihsm_buffer *info
);

/*
 @brief Set the policy flag bits

 Bits 0-2 are supported; reserved bits 3-7 are rejected at
 `azihsm_part_policy_build` time.

 @param[in] builder Builder handle
 @param[in] flags Raw flag bits (see the `PolicyFlags` definition)
 @return `AZIHSM_STATUS_SUCCESS`, or `AZIHSM_STATUS_INVALID_ARGUMENT` on a NULL handle

 # Safety

 - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
 */
azihsm_status azihsm_part_policy_builder_set_flags(
    struct azihsm_part_policy_builder *builder,
    uint8_t flags
);

/*
 @brief Serialize the policy into its canonical wire image

 Writes exactly `PART_POLICY_LEN` bytes — the image accepted by
 `azihsm_sess_ex_part_init` / `azihsm_sess_ex_part_final` — into
 `out`. If `out` is too small, sets `out.len` to the required size and
 returns `AZIHSM_STATUS_BUFFER_TOO_SMALL` without writing. The builder is left
 usable (unchanged) for further serialization.
 Both POTA and SATA keys must be set; otherwise returns
 `AZIHSM_STATUS_INVALID_ARGUMENT`, even for a size probe.
 Unsupported major versions and reserved flag bits also return
 `AZIHSM_STATUS_INVALID_ARGUMENT` before writing output.

 @param[in] builder Builder handle
 @param[out] out Buffer to receive the serialized policy image
 @return `AZIHSM_STATUS_SUCCESS`, `AZIHSM_STATUS_INVALID_ARGUMENT` on a
         NULL or misaligned handle / buffer, or
         `AZIHSM_STATUS_BUFFER_TOO_SMALL` if `out` is too small

 # Safety

 - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
 - `out` must be a valid pointer to an `azihsm_buffer` with writable
   backing storage of its advertised length.
 */
azihsm_status azihsm_part_policy_build(
    struct azihsm_part_policy_builder *builder,
    struct azihsm_buffer *out
);

/*
 Get the list of HSM partitions

 @param[out] handle Handle to the HSM partition list
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences a raw pointer.
 The caller must ensure that the pointer is valid and points to a valid `AzihsmHandle`.

 */
azihsm_status azihsm_part_get_list(azihsm_handle *handle);

/*
 Free the HSM partition list

 @param[in] handle Handle to the HSM partition list
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is marked unsafe due to unsafe(no_mangle).

 */
azihsm_status azihsm_part_free_list(azihsm_handle handle);

/*
 Get partition count

 @param[in] handle Handle to the HSM partition list
 @param[out] count Number of partitions
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences a raw pointer.
 The caller must ensure that handle is a valid `AzihsmHandle`.
 The caller must also ensure that the pointer is valid and points to a valid `AzihsmU32`.

 */
azihsm_status azihsm_part_get_count(azihsm_handle handle, uint32_t *count);

/*
 Get partition info at the given index

 @param[in] handle Handle to the HSM partition list
 @param[in] index Index of the partition
 @param[in/out] part_info Pointer to an `AzihsmPartInfo` structure.
                On input, `part_info.path.len` is the size of the buffer pointed to by
 `part_info.path.str`. On output, `part_info.path.len` is set to the required/written size.
                `part_info.api_rev_min` / `part_info.api_rev_max` are only valid on
                `AZIHSM_STATUS_SUCCESS`.

 @return 0 on success, AZIHSM_STATUS_BUFFER_TOO_SMALL if the path buffer is too small
         (part_info.path.len is updated to the required size), or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.

 */
azihsm_status azihsm_part_get_info(
    azihsm_handle handle,
    uint32_t index,
    struct azihsm_part_info *part_info
);

/*
 Open an HSM partition with a specified API revision

 The caller selects an API revision within the range reported by
 `azihsm_part_get_info`. All subsequent operations on this handle
 (including sessions opened from it) will use the selected revision.

 @param[in] path Pointer to an `azihsm_str` containing the partition
            device path. The `str` field must point to a valid
            null-terminated buffer and `len` must include the null
            terminator (i.e. `str[len-1] == 0`).
 @param[out] handle Handle to the opened HSM partition
 @param[in] api_rev API revision to use for this partition handle
 @return 0 on success, AZIHSM_STATUS_UNSUPPORTED_API_REVISION if api_rev is
         outside the partition's supported range, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 The caller must ensure that `path` is a valid pointer to an `AzihsmStr`
 whose `str` field points to a null-terminated buffer of `len`
 `azihsm_char` elements (including the terminator).
 The caller must also ensure that the `handle` argument is a valid `AzihsmHandle` pointer.

 */
azihsm_status azihsm_part_open(
    const struct azihsm_str *path,
    azihsm_handle *handle,
    struct azihsm_api_rev api_rev
);

/*
 Initialize an HSM partition

 @param[in] part_handle Handle to the HSM partition
 @param[in] creds Pointer to application credentials (ID and PIN)
 @param[in] bmk Optional backup masking key buffer (can be null)
 @param[in] muk Optional masked unwrapping key buffer (can be null)
 @param[in] backup_key_config Configuration for owner backup key
 @param[in] pota_endorsement POTA endorsement configuration
 @param[in] resiliency_config Optional resiliency configuration (can be null).
            When non-null, enables automatic retry/recovery for transient
            hardware resets. If POTA source is Caller, `pota_callback_ops`
            must be non-null. If POTA source is TPM, `pota_callback_ops`
            must be null.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.

 */
azihsm_status azihsm_part_init(
    azihsm_handle part_handle,
    const struct azihsm_credentials *creds,
    const struct azihsm_buffer *bmk,
    const struct azihsm_buffer *muk,
    const struct azihsm_owner_backup_key_config *backup_key_config,
    const struct azihsm_pota_endorsement *pota_endorsement,
    const struct azihsm_resiliency_config *resiliency_config
);

/*
 Close an HSM partition

 @param[in] handle Handle to the HSM partition
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences a raw pointer.
 This function is marked unsafe due to unsafe(no_mangle).

 */
azihsm_status azihsm_part_close(azihsm_handle handle);

/*
 Reset the HSM partition state

 including established credentials and active sessions. This is useful for
 test cleanup and recovery scenarios.

 @param[in] part_handle Handle to the HSM partition
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences a raw pointer.
 This function is marked unsafe due to unsafe(no_mangle).

 */
azihsm_status azihsm_part_reset(azihsm_handle part_handle);

/*
 Get a property of a partition

 @param[in] handle Handle to the partition
 @param[in/out] part_prop Pointer to partition property structure. On input, specifies which
 property to get. On output, contains the property value.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_part_get_prop(azihsm_handle handle, struct azihsm_part_prop *part_prop);

/*
 @brief Create a new security domain and its remote backup

 Creates a security domain under the calling session's partition from
 `params.part_policy`, using the sender's masked sealing key and the
 receiver's attestation evidence, and returns the three backups the
 firmware produces.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Create-backup input buffers
 @param[in,out] pok_remote_backup Output buffer for the remote
                partition-owner-key backup (161 B).
 @param[in,out] pok_local_backup Output buffer for the local
                partition-owner-key backup (276 B).
 @param[in,out] sd_mk_backup Output buffer for the security-domain
                masking-key backup (260 B).

 All three output buffers follow the probe/fill convention and are
 validated **before** the domain is created, so the one-shot command is
 not consumed when a buffer is too small.

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
 - Each output buffer must be a valid `azihsm_buffer` with writable
   backing storage of the advertised length.
 */
azihsm_status azihsm_sd_create_remote_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_create_remote_backup_params *params,
    struct azihsm_buffer *pok_remote_backup,
    struct azihsm_buffer *pok_local_backup,
    struct azihsm_buffer *sd_mk_backup
);

/*
 @brief Reseal an existing remote backup to a new recipient

 HPKE-opens `params.src_remote_backup` with the receiver's masked
 sealing key (authenticated by the source sender in `params.src_evidence`)
 and reseals the recovered backup to the destination receiver
 (`params.dest_evidence`), returning the resealed remote backup.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Reseal-backup input buffers
 @param[in,out] dst_remote_backup Output buffer for the resealed remote
                partition-owner-key backup (161 B).

 The output buffer follows the probe/fill convention and is validated
 **before** the reseal is performed.

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
 - `dst_remote_backup` must be a valid `azihsm_buffer` with writable
   backing storage of the advertised length.
 */
azihsm_status azihsm_sd_reseal_remote_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_reseal_remote_backup_params *params,
    struct azihsm_buffer *dst_remote_backup
);

/*
 @brief Restore a security domain from a remote backup

 HPKE-opens `params.src_remote_backup` with the receiver's masked sealing
 key (authenticated by the sender in `params.sender_evidence`), recovers
 the security-domain masking key from `params.prev_sd_mk_backup`, and
 returns the refreshed device-local backups.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Restore-backup input buffers
 @param[in,out] pok_local_backup Output buffer for the local
                partition-owner-key backup (276 B).
 @param[in,out] sd_mk_backup Output buffer for the security-domain
                masking-key backup (260 B).

 Both output buffers follow the probe/fill convention and are validated
 **before** the restore is performed.

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
 - Each output buffer must be a valid `azihsm_buffer` with writable
   backing storage of the advertised length.
 */
azihsm_status azihsm_sd_restore_remote_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_restore_remote_backup_params *params,
    struct azihsm_buffer *pok_local_backup,
    struct azihsm_buffer *sd_mk_backup
);

/*
 @brief Create a peer-transferable backup of a security domain

 Recovers BKS3 from `params.pok_local_backup` and HPKE-Auth-seals it to
 the destination peer named by `params.dst_evidence` (authenticated by
 the sender's masked sealing key), returning the peer backup. Gated by
 the security domain's `allow_peer_cloning` policy flag.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Create-peer-backup input buffers
 @param[in,out] pok_peer_backup Output buffer for the peer
                partition-owner-key backup (161 B).

 The output buffer follows the probe/fill convention and is validated
 **before** the peer backup is created.

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
 - `pok_peer_backup` must be a valid `azihsm_buffer` with writable
   backing storage of the advertised length.
 */
azihsm_status azihsm_sd_create_peer_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_create_peer_backup_params *params,
    struct azihsm_buffer *pok_peer_backup
);

/*
 @brief Restore a security domain from a peer backup

 HPKE-opens `params.pok_peer_backup` with the receiver's masked sealing
 key (authenticated by the source peer in `params.src_evidence`), recovers
 the security-domain masking key from `params.prev_sd_mk_backup`, and
 returns the refreshed device-local backups.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Restore-backup input buffers
 @param[in,out] pok_local_backup Output buffer for the local
                partition-owner-key backup (276 B).
 @param[in,out] sd_mk_backup Output buffer for the security-domain
                masking-key backup (260 B).

 Both output buffers follow the probe/fill convention and are validated
 **before** the restore is performed.

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `AzihsmSdCertChain.certs` must point to `len` valid `azihsm_buffer`s.
 - Each output buffer must be a valid `azihsm_buffer` with writable
   backing storage of the advertised length.
 */
azihsm_status azihsm_sd_restore_peer_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_restore_peer_backup_params *params,
    struct azihsm_buffer *pok_local_backup,
    struct azihsm_buffer *sd_mk_backup
);

/*
 @brief Restore a security domain from its device-local backups

 Restores the security domain from the device-local
 `params.pok_local_backup` and `params.sd_mk_backup`, returning the
 refreshed device-local backups. No attestation evidence is involved.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Restore-backup input buffers
 @param[in,out] pok_local_backup Output buffer for the refreshed local
                partition-owner-key backup (276 B).
 @param[in,out] sd_mk_backup Output buffer for the refreshed
                security-domain masking-key backup (260 B).

 Both output buffers follow the probe/fill convention and are validated
 **before** the restore is performed.

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer pointers must be valid.
 - Each output buffer must be a valid `azihsm_buffer` with writable
   backing storage of the advertised length.
 */
azihsm_status azihsm_sd_restore_local_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_restore_local_backup_params *params,
    struct azihsm_buffer *pok_local_backup,
    struct azihsm_buffer *sd_mk_backup
);

/*
 @brief Open an HSM session

 Opens a session using the API revision that was selected when the
 partition was opened with `azihsm_part_open`.

 @param[in] dev_handle Handle to the HSM partition
 @param[in] creds Pointer to the application credentials
 @param[in] seed Pointer to the optional seed buffer
 @param[out] sess_handle Pointer to the session handle to be allocated

 @return `AzihsmError` indicating the result of the operation

 # Safety

 - `dev_handle` must be a valid partition handle.
 - `creds` must be a valid pointer to an `AzihsmCredentials` structure.
 - `sess_handle` must be a valid pointer to memory where the session handle
   will be written.
 */
azihsm_status azihsm_sess_open(
    azihsm_handle dev_handle,
    const struct azihsm_credentials *creds,
    const struct azihsm_buffer *seed,
    azihsm_handle *sess_handle
);

/*
 @brief Close an HSM session

 @param[in] handle Handle to the HSM session

 @return `AzihsmError` indicating the result of the operation

 # Safety

 - `handle` must be a valid session handle previously returned by
   `azihsm_sess_open`.
 - The handle must not have been previously closed.
 - After this call, the handle becomes invalid and must not be used.
 */
azihsm_status azihsm_sess_close(azihsm_handle handle);

/*
 @brief Open a security-domain session to the device

 Opens a security-domain session using the API revision negotiated when
 the partition was opened, and returns a handle to the resulting
 session. `psk` selects the role slot and (optionally) the PSK, and
 `session_type` selects the channel integrity profile pinned for the
 session.

 @param[in] dev_handle Handle to the HSM partition
 @param[in] psk PSK credential — slot plus optional PSK
            (see `azihsm_session_psk`)
 @param[in] session_type Channel integrity profile to pin for the session
 @param[out] sess_handle Pointer to the session handle to be allocated

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `dev_handle` must be a valid partition handle.
 - `psk` must be a valid pointer to an `azihsm_session_psk` whose `psk`
   field is NULL or a valid `azihsm_buffer` holding exactly `AZIHSM_PSK_LEN`
   bytes.
 - `sess_handle` must be a valid pointer to memory where the session handle
   will be written.
 */
azihsm_status azihsm_sess_ex_open(
    azihsm_handle dev_handle,
    const struct azihsm_session_psk *psk,
    azihsm_session_ex_type session_type,
    azihsm_handle *sess_handle
);

/*
 @brief Provision a partition's security domain

 Initializes the partition from the machine seed and unified partition
 policy, together with the partition-owner (POTA), security-administrator
 (SATA), and optional secondary-owner (SAPOTA) trust-anchor thumbprints,
 returning the partition's certificate-signing request and attestation
 report.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Provisioning input buffers
            (see `azihsm_sess_ex_part_init_params`)
 @param[in,out] pta_csr Output buffer for the DER PKCS#10 CSR. On input
                `len` is the capacity; on success it is set to the number
                of bytes written. If the buffer is too small (or `ptr` is
                NULL with `len == 0`), `len` is set to the maximum possible
                output size (the buffer is validated up-front against a
                fixed wire-schema bound, so the probe reports that bound
                rather than the exact byte count for this device) and
                `AZIHSM_STATUS_BUFFER_TOO_SMALL` is returned **before** the
                partition is provisioned — so the standard two-call probe
                (call once with a zero-length buffer to learn the required
                capacity, then retry) is safe for this one-shot command.
                When either output buffer is too small, **both** `pta_csr`
                and `pta_report` have their `len` set to their maximum
                bound, so a single probe reports both required sizes. A
                buffer sized to that bound is always large enough; the
                `len` written on success is the exact number of bytes. A
                NULL `ptr` with a non-zero `len` is rejected with
                `AZIHSM_STATUS_INVALID_ARGUMENT`.
 @param[in,out] pta_report Output buffer for the attestation report, with
                the same capacity/length contract as `pta_csr`.

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` must be a valid pointer to an `azihsm_sess_ex_part_init_params`
   whose `mach_seed`, `part_policy`, `pota_thumbprint`, and
   `sata_thumbprint` are valid `azihsm_buffer` pointers, and whose
   `sapota_thumbprint` is NULL or a valid `azihsm_buffer` pointer.
 - `pta_csr` and `pta_report` must be valid pointers to distinct
   `azihsm_buffer` structures with writable backing storage of the
   advertised length.
 */
azihsm_status azihsm_sess_ex_part_init(
    azihsm_handle sess_handle,
    const struct azihsm_sess_ex_part_init_params *params,
    struct azihsm_buffer *pta_csr,
    struct azihsm_buffer *pta_report
);

/*
 @brief Finalize a partition's security domain

 Completes provisioning started by `azihsm_sess_ex_part_init`: re-supplies
 the unified partition policy and the PTA certificate chain (root to leaf),
 optionally restoring a prior `local_mk` backup, and returns the current
 `local_mk` backup envelope the firmware produced.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Finalization input buffers
            (see `azihsm_sess_ex_part_final_params`)
 @param[in,out] local_mk_backup Output buffer for the `local_mk` backup
                envelope. On input `len` is the capacity; on success it is
                set to the number of bytes written. If the buffer is too
                small (or `ptr` is NULL with `len == 0`), `len` is set to
                the maximum possible output size and
                `AZIHSM_STATUS_BUFFER_TOO_SMALL` is returned **before** the
                partition is finalized, so the standard two-call probe
                (call once with a zero-length buffer to learn the required
                capacity, then retry) is safe for this one-shot command. A
                NULL `ptr` with a non-zero `len` is rejected with
                `AZIHSM_STATUS_INVALID_ARGUMENT`.

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` must be a valid pointer to an `azihsm_sess_ex_part_final_params`
   whose `part_policy` is a valid `azihsm_buffer` pointer, whose
   `pta_cert_chain` points to `pta_cert_chain_len` valid `azihsm_buffer`s,
   and whose `prev_local_mk_backup` is NULL or a valid `azihsm_buffer`
   pointer.
 - `local_mk_backup` must be a valid pointer to an `azihsm_buffer` with
   writable backing storage of the advertised length.
 */
azihsm_status azihsm_sess_ex_part_final(
    azihsm_handle sess_handle,
    const struct azihsm_sess_ex_part_final_params *params,
    struct azihsm_buffer *local_mk_backup
);

/*
 @brief Rotate the calling session's partition PSK

 Replaces the PSK of the slot implied by the session role (CO session
 → CO, CU session → CU) with `new_psk`, sealed under the session key.
 Required once on a fresh partition to move past the default-PSK gate
 before provisioning.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] new_psk New PSK buffer; must be exactly `AZIHSM_PSK_LEN` (32 B)

 @return `AzihsmStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `new_psk` must be a valid pointer to an `azihsm_buffer` whose
   backing storage holds exactly `AZIHSM_PSK_LEN` bytes.
 */
azihsm_status azihsm_sess_ex_psk_change(
    azihsm_handle sess_handle,
    const struct azihsm_buffer *new_psk
);

/*
 Get a property of a session

 @param[in] handle Handle to the session
 @param[in/out] session_prop Pointer to session property structure. On input, specifies which
 property to get. On output, contains the property value.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_session_get_prop(
    azihsm_handle handle,
    struct azihsm_session_prop *session_prop
);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* AZIHSM_API_H */
