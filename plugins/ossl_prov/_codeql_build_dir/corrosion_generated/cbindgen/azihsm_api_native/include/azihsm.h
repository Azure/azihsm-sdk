/* Copyright (C) Microsoft Corporation. All rights reserved. */

#ifndef __AZIHSM_API_H__
#define __AZIHSM_API_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

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
  AZIHSM_STATUS_KEY_PROPERTY_NOT_PRESENT = -9,
  AZIHSM_STATUS_KEY_CLASS_NOT_SPECIFIED = -10,
  AZIHSM_STATUS_KEY_KIND_NOT_SPECIFIED = -11,
  AZIHSM_STATUS_INVALID_KEY = -12,
  AZIHSM_STATUS_UNSUPPORTED_KEY_KIND = -13,
  AZIHSM_STATUS_UNSUPPORTED_ALGORITHM = -14,
  AZIHSM_STATUS_INVALID_SIGNATURE = -15,
  AZIHSM_STATUS_INVALID_KEY_PROPS = -16,
  AZIHSM_STATUS_UNSUPPORTED_KEY_PROPERTY = -17,
  AZIHSM_STATUS_CERT_CHAIN_CHANGED = -18,
  AZIHSM_STATUS_INVALID_TWEAK = -19,
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
};
#ifndef __cplusplus
typedef uint32_t azihsm_key_kind;
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
   NIST P-256 curve (secp256r1), 256-bit security.
   */
  AZIHSM_ECC_CURVE_P256 = 1,
  /*
   NIST P-384 curve (secp384r1), 384-bit security.
   */
  AZIHSM_ECC_CURVE_P384 = 2,
  /*
   NIST P-521 curve (secp521r1), 521-bit security.
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
  C FFI structure representing a cryptographic algorithm.

 This structure is used to specify the algorithm identifier and
 any associated parameters for cryptographic operations in the HSM.

 # Safety
 When using this struct from C code:
 - `params` must point to valid memory for `len` bytes
 - `params` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management

 */
struct azihsm_algo {
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
 C FFI structure for a buffer

 # Safety
 When using this struct from C code:
 - `ptr` must point to valid memory for `len` bytes
 - `ptr` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management
 */
struct azihsm_buffer {
  void *ptr;
  uint32_t len;
};

/*
 C FFI structure for a single key property

 # Safety
 When using this struct from C code:
 - `val` must point to valid memory for `len` bytes
 - `val` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management

 */
struct azihsm_key_prop {
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
 C FFI structure for a list of key properties

 # Safety
 When using this struct from C code:
 - `props` must point to valid memory for `count` elements
 - Each element's `val` must point to valid memory for `len` bytes
 - The lifetimes of `props` and its elements must exceed the lifetime of this struct
 - Caller is responsible for proper memory management

 */
struct azihsm_key_prop_list {
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
 Wide character (UTF-16 for Windows)
 */
typedef uint16_t azihsm_char;
#endif

/*
 String
 */
struct azihsm_str {
#if !defined(_WIN32)
  /*
   Pointer to the string
   */
  azihsm_char *str
#endif
  ;
#if defined(_WIN32)
  /*
   Pointer to the string
   */
  azihsm_char *str
#endif
  ;
  /*
   Length of the string (including null terminator)
   */
  uint32_t len;
};

/*
 credentials structure used for authentication.

 This structure contains the identifier and PIN required
 to authenticate with the HSM.

 */
struct azihsm_credentials {
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
 API revision structure used to specify the desired API version.

 This structure allows clients to specify the major and minor version
 numbers of the API they wish to use. It is used to ensure compatibility
 between different versions of the HSM API.

 */
struct azihsm_api_rev {
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
 AES CBC parameters.
 */
struct azihsm_algo_aes_cbc_params {
  /*
   IV
   */
  uint8_t iv[16];
};

/*
 ECDH parameter structure matching C API
 */
struct azihsm_algo_ecdh_params {
  const struct azihsm_buffer *pub_key;
};

/*
 HKDF parameter structure matching C API
 */
struct azihsm_algo_hkdf_params {
  azihsm_algo_id hmac_algo_id;
  const struct azihsm_buffer *salt;
  const struct azihsm_buffer *info;
};

/*
 RSA PKCS OAEP encryption/decryption parameters matching C API.

 Defines parameters for OAEP (Optimal Asymmetric Encryption Padding) operations,
 which provide secure probabilistic encryption using a hash function, mask
 generation function (MGF1), and optional label for context binding.
 */
struct azihsm_algo_rsa_pkcs_oaep_params {
  /*
   Hash algorithm identifier used for OAEP padding
   */
  azihsm_algo_id hash_algo_id;
  /*
   MGF1 mask generation function identifier
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
struct azihsm_algo_rsa_aes_key_wrap_params {
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
struct azihsm_algo_rsa_aes_wrap_params {
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
struct azihsm_algo_rsa_pkcs_pss_params {
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
extern "C" {
#endif // __cplusplus

/*
 Compute cryptographic digest (hash) of data using the specified algorithm.

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[in] data Pointer to data buffer to be hashed
 @param[out] digest Pointer to digest output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_digest(azihsm_handle sess_handle,
                                  const struct azihsm_algo *algo,
                                  const struct azihsm_buffer *data,
                                  struct azihsm_buffer *digest);

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
azihsm_status azihsm_crypt_digest_init(azihsm_handle sess_handle,
                                       const struct azihsm_algo *algo,
                                       azihsm_handle *ctx_handle);

/*
 Update a streaming digest operation with more data.

 @param[in] ctx_handle Handle to the digest context
 @param[in] data Pointer to data buffer to digest

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_digest_update(azihsm_handle ctx_handle,
                                         const struct azihsm_buffer *data);

/*
 Finalize a streaming digest operation and produce the digest.

 @param[in] ctx_handle Handle to the digest context
 @param[out] digest Pointer to digest output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 AZIHSM_STATUS_INSUFFICIENT_BUFFER is returned.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_digest_final(azihsm_handle ctx_handle, struct azihsm_buffer *digest);

/*
 Encrypt data using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the encryption key
 @param[in] plain_text Pointer to plaintext data buffer
 @param[out] cipher_text Pointer to ciphertext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_encrypt(struct azihsm_algo *algo,
                                   azihsm_handle key_handle,
                                   const struct azihsm_buffer *plain_text,
                                   struct azihsm_buffer *cipher_text);

/*
 Decrypt data using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the decryption key
 @param[in] cipher_text Pointer to ciphertext data buffer
 @param[out] plain_text Pointer to plaintext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_decrypt(struct azihsm_algo *algo,
                                   azihsm_handle key_handle,
                                   const struct azihsm_buffer *cipher_text,
                                   struct azihsm_buffer *plain_text);

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
azihsm_status azihsm_crypt_encrypt_init(struct azihsm_algo *algo,
                                        azihsm_handle key_handle,
                                        azihsm_handle *ctx_handle);

/*
 Update streaming encryption operation with additional plaintext data.

 @param[in] ctx_handle Handle to the streaming encryption context
 @param[in] plain_text Pointer to plaintext data buffer to encrypt
 @param[out] cipher_text Pointer to ciphertext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.
 Note: Output may be less than input size if buffering occurs (e.g., for block alignment).

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_encrypt_update(azihsm_handle ctx_handle,
                                          const struct azihsm_buffer *plain_text,
                                          struct azihsm_buffer *cipher_text);

/*
 Finalize streaming encryption operation and retrieve any remaining ciphertext.

 @param[in] ctx_handle Handle to the streaming encryption context (consumed by this call)
 @param[out] cipher_text Pointer to ciphertext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_encrypt_final(azihsm_handle ctx_handle,
                                         struct azihsm_buffer *cipher_text);

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
azihsm_status azihsm_crypt_decrypt_init(struct azihsm_algo *algo,
                                        azihsm_handle key_handle,
                                        azihsm_handle *ctx_handle);

/*
 Update streaming decryption operation with additional ciphertext data.

 @param[in] ctx_handle Handle to the streaming decryption context
 @param[in] cipher_text Pointer to ciphertext data buffer to decrypt
 @param[out] plain_text Pointer to plaintext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.
 Note: Output may be less than input size if buffering occurs (e.g., for block alignment).

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_decrypt_update(azihsm_handle ctx_handle,
                                          const struct azihsm_buffer *cipher_text,
                                          struct azihsm_buffer *plain_text);

/*
 Finalize streaming decryption operation and retrieve any remaining plaintext.

 @param[in] sess_handle Handle to the HSM session
 @param[in] ctx_handle Handle to the streaming decryption context (consumed by this call)
 @param[out] plain_text Pointer to plaintext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_decrypt_final(azihsm_handle ctx_handle,
                                         struct azihsm_buffer *plain_text);

/*
 Sign data using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the signing key
 @param[in] data Pointer to data buffer to be signed
 @param[out] sig Pointer to signature output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_sign(struct azihsm_algo *algo,
                                azihsm_handle key_handle,
                                const struct azihsm_buffer *data,
                                struct azihsm_buffer *sig);

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
azihsm_status azihsm_crypt_verify(struct azihsm_algo *algo,
                                  azihsm_handle key_handle,
                                  const struct azihsm_buffer *data,
                                  const struct azihsm_buffer *sig);

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
azihsm_status azihsm_crypt_sign_init(struct azihsm_algo *algo,
                                     azihsm_handle key_handle,
                                     azihsm_handle *ctx_handle);

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
 Finalize streaming sign operation and retrieve signature.

 @param[in] ctx_handle Handle to the streaming sign context
 @param[out] sig Pointer to signature output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_sign_final(azihsm_handle ctx_handle, struct azihsm_buffer *sig);

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
azihsm_status azihsm_crypt_verify_init(struct azihsm_algo *algo,
                                       azihsm_handle key_handle,
                                       azihsm_handle *ctx_handle);

/*
 Update streaming verify operation with additional data.

 @param[in] ctx_handle Handle to the streaming verify context
 @param[in] data Pointer to data buffer that was signed

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_verify_update(azihsm_handle ctx_handle,
                                         const struct azihsm_buffer *data);

/*
 Finalize streaming verify operation and verify signature.

 @param[in] ctx_handle Handle to the streaming verify context
 @param[in] sig Pointer to signature buffer to verify

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_crypt_verify_final(azihsm_handle ctx_handle, const struct azihsm_buffer *sig);

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
azihsm_status azihsm_key_gen(azihsm_handle sess_handle,
                             const struct azihsm_algo *algo,
                             const struct azihsm_key_prop_list *key_props,
                             azihsm_handle *key_handle);

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
azihsm_status azihsm_key_gen_pair(azihsm_handle sess_handle,
                                  struct azihsm_algo *algo,
                                  const struct azihsm_key_prop_list *priv_key_props,
                                  const struct azihsm_key_prop_list *pub_key_props,
                                  azihsm_handle *priv_key_handle,
                                  azihsm_handle *pub_key_handle);

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
azihsm_status azihsm_key_derive(azihsm_handle sess_handle,
                                struct azihsm_algo *algo,
                                azihsm_handle base_key,
                                const struct azihsm_key_prop_list *key_props,
                                azihsm_handle *key_handle);

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
azihsm_status azihsm_key_unwrap(struct azihsm_algo *algo,
                                azihsm_handle unwrapping_key,
                                struct azihsm_buffer *wrapped_key,
                                const struct azihsm_key_prop_list *key_props,
                                azihsm_handle *key_handle);

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
azihsm_status azihsm_key_unwrap_pair(struct azihsm_algo *algo,
                                     azihsm_handle unwrapping_key,
                                     const struct azihsm_buffer *wrapped_key,
                                     const struct azihsm_key_prop_list *priv_key_props,
                                     const struct azihsm_key_prop_list *pub_key_props,
                                     azihsm_handle *priv_key_handle,
                                     azihsm_handle *pub_key_handle);

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
azihsm_status azihsm_key_unmask(azihsm_handle sess_handle,
                                azihsm_key_kind key_kind,
                                const struct azihsm_buffer *masked_key,
                                azihsm_handle *key_handle);

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
azihsm_status azihsm_key_unmask_pair(azihsm_handle sess_handle,
                                     azihsm_key_kind key_kind,
                                     const struct azihsm_buffer *masked_key,
                                     azihsm_handle *priv_key_handle,
                                     azihsm_handle *pub_key_handle);

/*
 Generate a key attestation report

 This function generates an attestation report for a key.

 @param[in] key_handle Handle to the key to attest
 @param[in] report_data Pointer to buffer containing custom data to include in the report (max 128 bytes)
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
azihsm_status azihsm_generate_key_report(azihsm_handle key_handle,
                                         const struct azihsm_buffer *report_data,
                                         struct azihsm_buffer *report);

/*
 Get a property of a key

 @param[in] key Handle to the key
 @param[in/out] key_prop Pointer to key property structure. On input, specifies which property to get. On output, contains the property value.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
azihsm_status azihsm_key_get_prop(azihsm_handle key_handle,
                                  struct azihsm_key_prop *key_prop);

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
 This function is makred unsafe due to unsafe(no_mangle).

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
 Get the partition path
 @param[in] handle Handle to the HSM partition list
 @param[in] index Index of the partition
 @param[in/out] On input, the length of the buffer pointed to by `path` in bytes.
                On output, the number of bytes written to the buffer.
 @param[out] path Buffer to receive the null-terminated partition path in UTF-8 format on Linux and UTF-16 format on Windows.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.

 */
azihsm_status azihsm_part_get_path(azihsm_handle handle,
                                   uint32_t index,
                                   struct azihsm_str *path);

/*
 Open an HSM partition

 @param[in] path Pointer to the partition path (null-terminated UTF-8 string on Linux and UTF-16 string on Windows)
 @param[out] handle Handle to the opened HSM partition
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 The caller must ensure that the `path` pointer is valid and points to a valid `c_void`
 that can be interpreted as a null-terminated UTF-8 string on Linux and UTF-16 string on Windows.
 The caller must also ensure that the `handle` argument is a valid  `AzihsmHandle` pointer.

 */
azihsm_status azihsm_part_open(const struct azihsm_str *path,
                               azihsm_handle *handle);

/*
 Initialize an HSM partition

 @param[in] part_handle Handle to the HSM partition
 @param[in] creds Pointer to application credentials (ID and PIN)
 @param[in] bmk Optional backup masking key buffer (can be null)
 @param[in] muk Optional masked unwrapping key buffer (can be null)
 @param[in] mobk Optional masked owner backup key buffer (can be null)

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.

 */
azihsm_status azihsm_part_init(azihsm_handle part_handle,
                               const struct azihsm_credentials *creds,
                               const struct azihsm_buffer *bmk,
                               const struct azihsm_buffer *muk,
                               const struct azihsm_buffer *mobk);

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
 @brief Open an HSM partition

 @param[in] dev_handle Handle to the HSM partition
 @param[in] api_rev Pointer to the API revision structure
 @param[in] creds Pointer to the application credentials
 @param[out] sess_handle Pointer to the session handle to be allocated

 @return `AzihsmError` indicating the result of the operation

 */
azihsm_status azihsm_sess_open(azihsm_handle dev_handle,
                               const struct azihsm_api_rev *api_rev,
                               const struct azihsm_credentials *creds,
                               azihsm_handle *sess_handle);

/*
 @brief Close an HSM session

 @param[in] handle Handle to the HSM session

 @return `AzihsmError` indicating the result of the operation

 */
azihsm_status azihsm_sess_close(azihsm_handle handle);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* __AZIHSM_API_H__ */
