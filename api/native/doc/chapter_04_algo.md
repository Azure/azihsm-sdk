# Algorithms 

Following are the support cryptographic algorithms

## Manticore Masking Key Generation

WIP

## RSA PKCS#1 v1.5 Key Generation

Generates an RSA Key pair as defined in [PKCS #1: RSA Encryption Version 1.5](https://datatracker.ietf.org/doc/html/rfc2313). 
The keys are generated with public exponent of 65537.

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN`                       |
| **Params**                 | None                                                         |
| **Required Properties**    | ***Public Key Properties***                                  |
|                            | \small - `AZIHSM_KEY_PROP_ID_BIT_LEN`                        |
|                            | ***Private Key  Properties***                                |
|                            | \small - none                                                |
| **Contributed Properties** | ***Public Key Properties***                                  |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                          |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                           |
|                            | \small - `AZIHSM_KEY_PROP_PUB_KEY_INFO`                      |
|                            | ***Private Key Properties***                                 |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                          |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                           |
|                            | \small - `AZIHSM_KEY_PROP_PUB_KEY_INFO`                      |
| **Supported Operations**   | [azihsm_key_gen_pair](#azihsm_key_gen_pair)                  |
| **PKCS#11 Mechanism**      | CKM_RSA_PKCS_KEY_PAIR_GEN                             &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 Sign & Verify

The PKCS #1 v1.5 RSA algorithm, is a signing and verification mechanism based on the RSA public-key crypto system 
and the block formats initially defined in [PKCS #1: RSA Encryption Version 1.5](https://datatracker.ietf.org/doc/html/rfc2313). 
This algorithm does not compute a message digest as specified in PKCS #1 v1.5.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS`                                   |
| **Params**                 | None                                                        |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                     |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)           |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)       |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)         |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                 |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)       |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)   |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)     |
| **PKCS#11 Mechanism**      | CKM_RSA_PKCS                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 SHA-1 Sign & Verify

The PKCS #1 v1.5 RSA algorithm for signing and verification with SHA-1. The algorithm performs
digest operation on the data using SHA-1 algorithm.

|                            |                                                           |
| -------------------------- | --------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_SHA1`                            |
| **Params**                 | None                                                      |
| **Required Properties**    | None                                                      |
| **Contributed Properties** | None                                                      |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                   |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)         |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)     |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)       |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)               |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)     |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update) |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)   |
| **PKCS#11 Mechanism**      | CKM_SHA1_RSA_PKCS                                  &nbsp; |


**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_SHA1,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 SHA-256 Sign & Verify

The PKCS #1 v1.5 RSA algorithm for signing and verification with SHA-256. The algorithm performs
digest operation on the data using SHA-256 algorithm.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_SHA256`                            |
| **Params**                 | None                                                        |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                     |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)           |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)       |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)         |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                 |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)       |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)   |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)     |
| **PKCS#11 Mechanism**      | CKM_SHA256_RSA_PKCS                                  &nbsp; |


**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_SHA256,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 SHA-384 Sign & Verify

The PKCS #1 v1.5 RSA algorithm for signing and verification with SHA-384. The algorithm performs
digest operation on the data using SHA-384 algorithm.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_SHA384`                            |
| **Params**                 | None                                                        |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                     |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)           |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)       |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)         |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                 |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)       |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)   |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)     |
| **PKCS#11 Mechanism**      | CKM_SHA384_RSA_PKCS                                  &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_SHA384,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 SHA-512 Sign & Verify

The PKCS #1 v1.5 RSA algorithm for signing and verification with SHA-512. The algorithm performs
digest operation on the data using SHA-512 algorithm.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_SHA512`                            |
| **Params**                 | None                                                        |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                     |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)           |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)       |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)         |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                 |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)       |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)   |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)     |
| **PKCS#11 Mechanism**      | CKM_SHA512_RSA_PKCS                                  &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_SHA512,
    .params = NULL,
    .len = 0,
};
```


## RSA PKCS#1 PSS Sign & Verify

The PKCS #1 RSA PSS is a mechanism based on the RSA public-key crypto system and the PSS block 
format defined in [PKCS #1: RSA Encryption Version 1.5](https://datatracker.ietf.org/doc/html/rfc2313).
This algorithm does not compute a message digest as specified in PKCS #1 v1.5.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_PSS`                                       |
| **Params**                 | [azihsm_algo_rsa_pkcs_pss_params](#azihsm_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                             |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)                   |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)               |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)                 |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                         |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)               |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)           |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)             |
| **PKCS#11 Mechanism**      | CKM_RSA_PKCS_PSS                                                    |


**Example**
```cpp
struct azihsm_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
    .mgf_id = AZIHSM_MGF1_ID_SHA256,
    .salt_len = 0,
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct azihsm_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 PSS SHA-1 Sign & Verify

The PKCS#1 PSS RSA algorithm for signing and verification with SHA-1. The algorithm performs
digest operation on the data using SHA-1 algorithm.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA1`                                  |
| **Params**                 | [azihsm_algo_rsa_pkcs_pss_params](#azihsm_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                             |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)                   |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)               |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)                 |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                         |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)               |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)           |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)             |
| **PKCS#11 Mechanism**      | CKM_SHA1_RSA_PKCS_PSS                                               |


**Example**
```cpp
// Note: hash_algo_id and mgf_id must use SHA-1   
struct azihsm_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = AZIHSM_ALGO_ID_SHA1,
    .mgf_id = AZIHSM_MGF1_ID_SHA1,
    .salt_len = 0,
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct azihsm_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 PSS SHA-256 Sign & Verify

The PKCS#1 PSS RSA algorithm for signing and verification with SHA-256. The algorithm performs
digest operation on the data using SHA-256 algorithm.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA256`                                |
| **Params**                 | [azihsm_algo_rsa_pkcs_pss_params](#azihsm_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                             |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)                   |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)               |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)                 |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                         |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)               |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)           |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)             |
| **PKCS#11 Mechanism**      | CKM_SHA256_RSA_PKCS_PSS                                             |


**Example**
```cpp
// Note: hash_algo_id and mgf_id must use SHA-256   
struct azihsm_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
    .mgf_id = AZIHSM_MGF1_ID_SHA256,
    .salt_len = 0,
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct azihsm_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 PSS SHA-384 Sign & Verify

The PKCS#1 PSS RSA algorithm for signing and verification with SHA-384. The algorithm performs
digest operation on the data using SHA-384 algorithm.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA384`                                |
| **Params**                 | [azihsm_algo_rsa_pkcs_pss_params](#azihsm_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                             |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)                   |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)               |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)                 |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                         |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)               |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)           |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)             |
| **PKCS#11 Mechanism**      | CKM_SHA384_RSA_PKCS_PSS                                             |


**Example**
```cpp
// Note: hash_algo_id and mgf_id must use SHA-384   
struct azihsm_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = AZIHSM_ALGO_ID_SHA384,
    .mgf_id = AZIHSM_MGF1_ID_SHA384,
    .salt_len = 0,
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct azihsm_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 PSS SHA-512 Sign & Verify

The PKCS#1 PSS RSA algorithm for signing and verification with SHA-512. The algorithm performs
digest operation on the data using SHA-512 algorithm.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA512`                                |
| **Params**                 | [azihsm_algo_rsa_pkcs_pss_params](#azihsm_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                             |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)                   |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)               |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)                 |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                         |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)               |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)           |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)             |
| **PKCS#11 Mechanism**      | CKM_SHA512_RSA_PKCS_PSS                                             |


**Example**
```cpp
// Note: hash_algo_id and mgf_id must use SHA-512   
struct azihsm_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = AZIHSM_ALGO_ID_SHA512,
    .mgf_id = AZIHSM_MGF1_ID_SHA512,
    .salt_len = 0,
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct azihsm_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 OAEP Encrypt & Decrypt

The PKCS#1 RSA OAEP  is a multi-purpose mechanism based on the RSA public-key crypto system and the 
OAEP block format defined in PKCS#1.  It supports single-part encryption and decryption.

|                            |                                                                       |
| -------------------------- | --------------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_PKCS_OAEP`                                        |
| **Params**                 | [azihsm_algo_rsa_pkcs_oaep_params](#azihsm_algo_rsa_pkcs_oaep_params) |
| **Required Properties**    | None                                                                  |
| **Contributed Properties** | None                                                                  |
| **Supported Operations**   | [azihsm_crypt_encrypt](#azihsm_crypt_encrypt)                         |
|                            | [azihsm_crypt_encrypt_init](#azihsm_crypt_encrypt_init)               |
|                            | [azihsm_crypt_encrypt_update](#azihsm_crypt_encrypt_update)           |
|                            | [azihsm_crypt_encrypt_final](#azihsm_crypt_encrypt_final)             |
|                            | [azihsm_crypt_decrypt](#azihsm_crypt_decrypt)                         |
|                            | [azihsm_crypt_decrypt_init](#azihsm_crypt_decrypt_init)               |
|                            | [azihsm_crypt_decrypt_update](#azihsm_crypt_decrypt_update)           |
|                            | [azihsm_crypt_decrypt_final](#azihsm_crypt_decrypt_final)             |
| **PKCS#11 Mechanism**      | CKM_RSA_PKCS_OAEP                                                     |

**Example**
```cpp
struct azihsm_buffer label = {
    .buf = NULL,
    .len = 0,
};

// Note: hash_algo_id and mgf_id must use the same hash algorithm
struct azihsm_algo_rsa_pkcs_oaep_params params = {
    .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
    .mgf_id = AZIHSM_MGF1_ID_SHA256,
    .label = &label,
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_PKCS_OAEP,
    .params = &params,
    .len = sizeof(struct azihsm_algo_rsa_pkcs_oaep_params),
};
```

## RSA AES Key Wrap & Unwrap

The RSA AES key wrap is an algorithm based on the RSA public-key cryptos system and the AES key wrap algorithm. 
The algorithm can wrap and unwrap a target asymmetric key of any length and type using an RSA key.

- A temporary AES key is used for wrapping the target key using AZIHSM_ALGO_ID_AES_KEY_WRAP_KWP mechanism.
- The temporary AES key is wrapped with the wrapping RSA key using AZIHSM_ALGO_ID_RSA_PKCS_OAEP mechanism.

|                            |                                                                             |
| -------------------------- | --------------------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP`                                            |
| **Params**                 | [azihsm_algo_rsa_aes_key_wrap_params](#azihsm_algo_rsa_aes_key_wrap_params) |
| **Required Properties**    | None                                                                        |
| **Contributed Properties** | None                                                                        |
| **Supported Operations**   | [azihsm_key_unwrap](#azihsm_key_unwrap)                                     |
| **PKCS#11 Mechanism**      | CKM_RSA_AES_KEY_WRAP                                                        |

```cpp
struct azihsm_buffer label = {
    .buf = NULL,
    .len = 0,
};

// Note: hash_algo_id and mgf_id must use the same hash algorithm
struct azihsm_algo_rsa_pkcs_oaep_params oaep_params = {
    .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
    .mgf_id = AZIHSM_MGF1_ID_SHA256,
    .label = &label,
};

struct azihsm_algo_rsa_aes_key_wrap_params params = {
    .aes_key_bits = 256,
    .oaep_params = &oaep_params,
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP,
    .params = &params,
    .len = sizeof(struct azihsm_algo_rsa_aes_key_wrap_params),
};
```

## EC Key Pair Generation

The EC (also related to ECDSA) key pair generation is an algorithm, that uses the method defined
by [SEC 1: Elliptic Curve Cryptography, Version 2.0](https://www.secg.org/sec1-v2.pdf).

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN`                             |
| **Params**                 | None                                                         |
| **Required Properties**    | ***Public Key Properties***                                  |
|                            | \small - `AZIHSM_KEY_PROP_ID_EC_CURVE`                       |
|                            | ***Private Key  Properties***                                |
|                            | \small - none                                                |
| **Contributed Properties** | ***Public Key Properties***                                  |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                          |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                           |
|                            | \small - `AZIHSM_KEY_PROP_PUB_KEY_INFO`                      |
|                            | ***Private Key Properties***                                 |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                          |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                           |
|                            | \small - `AZIHSM_KEY_PROP_PUB_KEY_INFO`                      |
| **Supported Operations**   | [azihsm_key_gen_pair](#azihsm_key_gen_pair)                  |
| **PKCS#11 Mechanism**      | CKM_EC_KEY_PAIR_GEN                                   &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
    .params = NULL,
    .len = 0,
};
```

## ECDSA Sign & Verify

ECDSA without hashing is an algorithm for single-part signatures and verification for ECDSA.

|                            |                                                           |
| -------------------------- | --------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_ECDSA`                                    |
| **Params**                 | None                                                      |
| **Required Properties**    | None                                                      |
| **Contributed Properties** | None                                                      |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                   |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)         |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)     |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)       |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)               |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)     |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update) |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)   |
| **PKCS#11 Mechanism**      | CKM_ECDSA                                         &nbsp;  |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_ECDSA,
    .params = NULL,
    .len = 0,
};
```

## ECDSA SHA-1 Sign & Verify

ECDSA with hashing is an algorithm for single-part & multi-part signatures and verification
for ECDSA. This mechanism computes the entire ECDSA specification, including the hashing
with SHA-1

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_ECDSA_SHA1`                                    |
| **Params**                 | None                                                           |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                        |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)              |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)          |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)            |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                    |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)          |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)      |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)        |
| **PKCS#11 Mechanism**      | CKM_ECDSA_SHA_1                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_ECDSA_SHA1,
    .params = NULL,
    .len = 0,
};
```

## ECDSA SHA-256 Sign & Verify

ECDSA with hashing is an algorithm for single-part & multi-part signatures and verification
for ECDSA. This mechanism computes the entire ECDSA specification, including the hashing
with SHA-256

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_ECDSA_SHA256`                                |
| **Params**                 | None                                                         |
| **Required Properties**    | None                                                         |
| **Contributed Properties** | None                                                         |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                      |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)            |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)        |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)          |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                  |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)        |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)    |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)      |
| **PKCS#11 Mechanism**      | CKM_ECDSA_256                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
    .params = NULL,
    .len = 0,
};
```

## ECDSA SHA-384 Sign & Verify

ECDSA with hashing is an algorithm for single-part & multi-part signatures and verification
for ECDSA. This mechanism computes the entire ECDSA specification, including the hashing
with SHA-384

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_ECDSA_SHA384`                                |
| **Params**                 | None                                                         |
| **Required Properties**    | None                                                         |
| **Contributed Properties** | None                                                         |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                      |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)            |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)        |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)          |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                  |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)        |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)    |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)      |
| **PKCS#11 Mechanism**      | CKM_ECDSA_384                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_ECDSA_SHA384,
    .params = NULL,
    .len = 0,
};
```

## ECDSA SHA-512 Sign & Verify

ECDSA with hashing is an algorithm for single-part & multi-part signatures and verification
for ECDSA. This mechanism computes the entire ECDSA specification, including the hashing
with SHA-512

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_ECDSA_SHA512`                                |
| **Params**                 | None                                                         |
| **Required Properties**    | None                                                         |
| **Contributed Properties** | None                                                         |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                      |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)            |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)        |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)          |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                  |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)        |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)    |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)      |
| **PKCS#11 Mechanism**      | CKM_ECDSA_512                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_ECDSA_SHA512,
    .params = NULL,
    .len = 0,
};
```

## ECDH Derive

The elliptic curve Diffie-Hellman (ECDH) key derivation ,is an algorithm for key derivation based 
on the Diffie-Hellman version of the elliptic curve key agreement scheme, as defined in 
[SEC 1: Elliptic Curve Cryptography, Version 2.0](https://www.secg.org/sec1-v2.pdf), where each party 
contributes one key pair all using the same EC domain parameters.

|                            |                                                                 |
| -------------------------- | --------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_ECDH`                                           |
| **Params**                 | [azihsm_algo_ecdh_params](#azihsm_algo_ecdh_params)             |
| **Required Properties**    | None                                                            |
| **Contributed Properties** | None                                                            |
| **Supported Operations**   | [azihsm_key_derive](#azihsm_key_derive)                         |
| **PKCS#11 Mechanism**      | CKM_ECDH1_DERIVE                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo_ecdh_params params = {
    .pub_key = pub_key,
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_ECDH,
    .params = &params,
    .len = sizeof(struct azihsm_algo_ecdh_params),
};
```

## AES Key Generation

The AES key generation is a key generation algorithm for 
[NIST FIPS 197 Advanced Encryption Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).

|                            |                                                          |
| -------------------------- | -------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_AES_KEY_GEN`                             |
| **Params**                 | None                                                     |
| **Required Properties**    | ***Public Key Properties***                              |
|                            | \small - `AZIHSM_KEY_PROP_ID_BIT_LEN`                    |
|                            | ***Private Key  Properties***                            |
|                            | \small - none                                            |
| **Contributed Properties** | ***Public Key Properties***                              |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                      |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                       |
|                            | ***Private Key Properties***                             |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                      |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                       |
| **Supported Operations**   | [azihsm_key_gen](#azihsm_key_gen)                        |
| **PKCS#11 Mechanism**      | CKM_AES_KEY_GEN                                   &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
    .params = NULL,
    .len = 0,
};
```

## AES CBC Encrypt & Decrypt

AES-CBC is an algorithm for symmetric block encryption as defined by
[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_AES_CBC`                                    |
| **Params**                 | [azihsm_algo_aes_cbc_params](#azihsm_algo_aes_cbc_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [azihsm_crypt_encrypt](#azihsm_crypt_encrypt)               |
|                            | [azihsm_crypt_encrypt_init](#azihsm_crypt_encrypt_init)     |
|                            | [azihsm_crypt_encrypt_update](#azihsm_crypt_encrypt_update) |
|                            | [azihsm_crypt_encrypt_final](#azihsm_crypt_encrypt_final)   |
|                            | [azihsm_crypt_decrypt](#azihsm_crypt_decrypt)               |
|                            | [azihsm_crypt_decrypt_init](#azihsm_crypt_decrypt_init)     |
|                            | [azihsm_crypt_decrypt_update](#azihsm_crypt_decrypt_update) |
|                            | [azihsm_crypt_decrypt_final](#azihsm_crypt_decrypt_final)   |
| **PKCS#11 Mechanism**      | CKM_AES_CBC                                         &nbsp;  |

**Example**

```cpp
struct azihsm_buffer iv = {
    .buf = some_iv,
    .len = 16,
};

struct azihsm_algo_aes_cbc_params params = {
    .iv = &iv
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_AES_CBC,
    .params = &params,
    .len = sizeof(struct azihsm_algo_aes_cbc_params),
};
```

## AES CBC Pad Encrypt & Decrypt

AES-CBC is an algorithm for symmetric block encryption as defined by
[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).
This algorithm performs padding based on [PKCS#7](https://datatracker.ietf.org/doc/html/rfc2315)

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_AES_CBC_PAD`                                |
| **Params**                 | [azihsm_algo_aes_cbc_params](#azihsm_algo_aes_cbc_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [azihsm_crypt_encrypt](#azihsm_crypt_encrypt)               |
|                            | [azihsm_crypt_encrypt_init](#azihsm_crypt_encrypt_init)     |
|                            | [azihsm_crypt_encrypt_update](#azihsm_crypt_encrypt_update) |
|                            | [azihsm_crypt_encrypt_final](#azihsm_crypt_encrypt_final)   |
|                            | [azihsm_crypt_decrypt](#azihsm_crypt_decrypt)               |
|                            | [azihsm_crypt_decrypt_init](#azihsm_crypt_decrypt_init)     |
|                            | [azihsm_crypt_decrypt_update](#azihsm_crypt_decrypt_update) |
|                            | [azihsm_crypt_decrypt_final](#azihsm_crypt_decrypt_final)   |
| **PKCS#11 Mechanism**      | CKM_AES_CBC_PAD                                      &nbsp; |

**Example**

```cpp
struct azihsm_algo_aes_cbc_params params = {
    .iv = {0}
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
    .params = &params,
    .len = sizeof(struct azihsm_algo_aes_cbc_params),
};
```

## AES XTS Key Generation

The double-length AES-XTS key generation is an algorithm for generating double-length AES-XTS keys. 
Supported key lengths are 64 bytes. Keys are internally split into half-length sub-keys of 32 bytes.

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_AES_XTS_KEY_GEN`                             |
| **Params**                 | None                                                         |
| **Required Properties**    | ***Public Key Properties***                                  |
|                            | \small - `AZIHSM_KEY_PROP_ID_BIT_LEN`                        |
|                            | ***Private Key  Properties***                                |
|                            | \small - none                                                |
| **Contributed Properties** | ***Public Key Properties***                                  |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                          |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                           |
|                            | ***Private Key Properties***                                 |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                          |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                           |
| **Supported Operations**   | [azihsm_key_gen](#azihsm_key_gen)                            |
| **PKCS#11 Mechanism**      | CKM_AES_XTS_KEY_GEN                                   &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
    .params = NULL,
    .len = 0,
};
```

## AES XTS Encrypt & Decrypt

AES-XTS (XEX-based Tweaked CodeBook mode with CipherText Stealing), is an algorithm for single and multiple-part 
encryption and decryption. It is specified in [NIST SP800-38E](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf).

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_AES_XTS`                                    |
| **Params**                 | [azihsm_algo_aes_xts_params](#azihsm_algo_aes_xts_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [azihsm_crypt_encrypt](#azihsm_crypt_encrypt)               |
|                            | [azihsm_crypt_encrypt_init](#azihsm_crypt_encrypt_init)     |
|                            | [azihsm_crypt_encrypt_update](#azihsm_crypt_encrypt_update) |
|                            | [azihsm_crypt_encrypt_final](#azihsm_crypt_encrypt_final)   |
|                            | [azihsm_crypt_decrypt](#azihsm_crypt_decrypt)               |
|                            | [azihsm_crypt_decrypt_init](#azihsm_crypt_decrypt_init)     |
|                            | [azihsm_crypt_decrypt_update](#azihsm_crypt_decrypt_update) |
|                            | [azihsm_crypt_decrypt_final](#azihsm_crypt_decrypt_final)   |
| **PKCS#11 Mechanism**      | CKM_AES_XTS                                         &nbsp;  |

**Example**

```cpp
struct azihsm_algo_aes_xts_params params = {
    .sector_num = {0}
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_AES_XTS,
    .params = &params,
    .len = sizeof(struct azihsm_algo_aes_xts_params),
};
```
## AES GCM Key Generation

The AES-GCM key generation is an algorithm for generating AES keys used with the GCM (Galois/Counter Mode) authenticated encryption mode as defined by [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_AES_GCM_KEY_GEN`                             |
| **Params**                 | None                                                         |
| **Required Properties**    | ***Public Key Properties***                                  |
|                            | \small - `AZIHSM_KEY_PROP_ID_BIT_LEN`                        |
|                            | ***Private Key  Properties***                                |
|                            | \small - none                                                |
| **Contributed Properties** | ***Public Key Properties***                                  |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                          |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                           |
|                            | ***Private Key Properties***                                 |
|                            | \small - `AZIHSM_KEY_PROP_ID_CLASS`                          |
|                            | \small - `AZIHSM_KEY_PROP_ID_TYPE`                           |
| **Supported Operations**   | [azihsm_key_gen](#azihsm_key_gen)                            |
| **PKCS#11 Mechanism**      | CKM_AES_GCM_KEY_GEN                                   &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
    .params = NULL,
    .len = 0,
};
```

## AES GCM Encrypt & Decrypt

AES-GCM is an authenticated encryption algorithm as defined by
[NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_AES_GCM`                                    |
| **Params**                 | [azihsm_algo_aes_gcm_params](#azihsm_algo_aes_gcm_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [azihsm_crypt_encrypt](#azihsm_crypt_encrypt)               |
|                            | [azihsm_crypt_encrypt_init](#azihsm_crypt_encrypt_init)     |
|                            | [azihsm_crypt_encrypt_update](#azihsm_crypt_encrypt_update) |
|                            | [azihsm_crypt_encrypt_final](#azihsm_crypt_encrypt_final)   |
|                            | [azihsm_crypt_decrypt](#azihsm_crypt_decrypt)               |
|                            | [azihsm_crypt_decrypt_init](#azihsm_crypt_decrypt_init)     |
|                            | [azihsm_crypt_decrypt_update](#azihsm_crypt_decrypt_update) |
|                            | [azihsm_crypt_decrypt_final](#azihsm_crypt_decrypt_final)   |
| **PKCS#11 Mechanism**      | CKM_AES_GCM                                         &nbsp;  |

**Example**

```cpp
struct azihsm_buffer aad = {
    .buf = some_aad,
    .len = aad_len,
};

struct azihsm_algo_aes_gcm_params params = {
    .iv = {0},
    .tag = {0},
    .aad = &aad,
};

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_AES_GCM,
    .params = &params,
    .len = sizeof(struct azihsm_algo_aes_gcm_params),
};
```

## SHA-1 Digest

The SHA-1 is an algorithm for message digesting data. It generates a 160-bit message digest as defined in 
[FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_SHA1`                                        |
| **Params**                 | None                                                         |
| **Required Properties**    | None                                                         |
| **Contributed Properties** | None                                                         |
| **Supported Operations**   | [azihsm_crypt_digest](#azihsm_crypt_digest)                  |
|                            | [azihsm_crypt_digest_init](#azihsm_crypt_digest_init)        |
|                            | [azihsm_crypt_digest_update](#azihsm_crypt_digest_update)    |
|                            | [azihsm_crypt_digest_final](#azihsm_crypt_digest_final)      |
| **PKCS#11 Mechanism**      | CKM_SHA_1                                             &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_SHA1,
    .params = NULL,
    .len = 0,
};
```

## SHA-256 Digest

The SHA-256 is an algorithm for message digesting data. It generates a 256-bit message digest as defined in 
[FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

|                            |                                                               |
| -------------------------- | ------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_SHA256`                                       |
| **Params**                 | None                                                          |
| **Required Properties**    | None                                                          |
| **Contributed Properties** | None                                                          |
| **Supported Operations**   | [azihsm_crypt_digest](#azihsm_crypt_digest)                   |
|                            | [azihsm_crypt_digest_init](#azihsm_crypt_digest_init)         |
|                            | [azihsm_crypt_digest_update](#azihsm_crypt_digest_update)     |
|                            | [azihsm_crypt_digest_final](#azihsm_crypt_digest_final)       |
| **PKCS#11 Mechanism**      | CKM_SHA256                                             &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_SHA256,
    .params = NULL,
    .len = 0,
};
```

## SHA-384 Digest

The SHA-384 is an algorithm for message digesting data. It generates a 384-bit message digest as defined in 
[FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

|                            |                                                               |
| -------------------------- | ------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_SHA384`                                       |
| **Params**                 | None                                                          |
| **Required Properties**    | None                                                          |
| **Contributed Properties** | None                                                          |
| **Supported Operations**   | [azihsm_crypt_digest](#azihsm_crypt_digest)                   |
|                            | [azihsm_crypt_digest_init](#azihsm_crypt_digest_init)         |
|                            | [azihsm_crypt_digest_update](#azihsm_crypt_digest_update)     |
|                            | [azihsm_crypt_digest_final](#azihsm_crypt_digest_final)       |
| **PKCS#11 Mechanism**      | CKM_SHA384                                             &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_SHA384,
    .params = NULL,
    .len = 0,
};
```

## SHA-512 Digest

The SHA-512 is an algorithm for message digesting data. It generates a 512-bit message digest as defined in 
[FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

|                            |                                                               |
| -------------------------- | ------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_SHA512`                                       |
| **Params**                 | None                                                          |
| **Required Properties**    | None                                                          |
| **Contributed Properties** | None                                                          |
| **Supported Operations**   | [azihsm_crypt_digest](#azihsm_crypt_digest)                   |
|                            | [azihsm_crypt_digest_init](#azihsm_crypt_digest_init)         |
|                            | [azihsm_crypt_digest_update](#azihsm_crypt_digest_update)     |
|                            | [azihsm_crypt_digest_final](#azihsm_crypt_digest_final)       |
| **PKCS#11 Mechanism**      | CKM_SHA512                                             &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_SHA512,
    .params = NULL,
    .len = 0,
};
```

## HMAC SHA-1 Sign & Verify

The SHA-1 HMAC is an algorithm for signatures and verification. It uses the HMAC construction, 
based on the SHA-1 hash function.

|                            |                                                               |
| -------------------------- | ------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_HMAC_SHA1`                                    |
| **Params**                 | None                                                          |
| **Required Properties**    | None                                                          |
| **Contributed Properties** | None                                                          |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                       |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)             |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)         |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)           |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                   |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)         |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)     |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)       |
| **PKCS#11 Mechanism**      | CKM_SHA_1_HMAC                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_HMAC_SHA1,
    .params = NULL,
    .len = 0,
};
```

## HMAC SHA-256 Sign & Verify

The SHA-256 HMAC is an algorithm for signatures and verification. It uses the HMAC construction, 
based on the SHA-256 hash function.

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_HMAC_SHA256`                                   |
| **Params**                 | None                                                           |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                        |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)              |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)          |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)            |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                    |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)          |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)      |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)        |
| **PKCS#11 Mechanism**      | CKM_SHA256_HMAC                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_HMAC_SHA256,
    .params = NULL,
    .len = 0,
};
```

## HMAC SHA-384 Sign & Verify

The SHA-384 HMAC is an algorithm for signatures and verification. It uses the HMAC construction, 
based on the SHA-384 hash function.

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_HMAC_SHA384`                                   |
| **Params**                 | None                                                           |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                        |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)              |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)          |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)            |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                    |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)          |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)      |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)        |
| **PKCS#11 Mechanism**      | CKM_SHA384_HMAC                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_HMAC_SHA384,
    .params = NULL,
    .len = 0,
};
```

## HMAC SHA-512 Sign & Verify

The SHA-512 HMAC is an algorithm for signatures and verification. It uses the HMAC construction, 
based on the SHA-512 hash function.

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_HMAC_SHA512`                                   |
| **Params**                 | None                                                           |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [azihsm_crypt_sign](#azihsm_crypt_sign)                        |
|                            | [azihsm_crypt_sign_init](#azihsm_crypt_sign_init)              |
|                            | [azihsm_crypt_sign_update](#azihsm_crypt_sign_update)          |
|                            | [azihsm_crypt_sign_final](#azihsm_crypt_sign_final)            |
|                            | [azihsm_crypt_verify](#azihsm_crypt_verify)                    |
|                            | [azihsm_crypt_verify_init](#azihsm_crypt_verify_init)          |
|                            | [azihsm_crypt_verify_update](#azihsm_crypt_verify_update)      |
|                            | [azihsm_crypt_verify_final](#azihsm_crypt_verify_final)        |
| **PKCS#11 Mechanism**      | CKM_SHA512_HMAC                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_HMAC_SHA512,
    .params = NULL,
    .len = 0,
};
```

## HKDF Derive

HKDF derivation implements the KDF as specified in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_HKDF_DERIVE`                                   |
| **Params**                 | [azihsm_algo_hkdf_params](#azihsm_algo_hkdf_params)            |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [azihsm_key_derive](#azihsm_key_derive)                        |
| **PKCS#11 Mechanism**      | CKM_HKDF_DERIVE                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo_hkdf_params params = {
    .hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA512,
    .salt = NULL,
    .info = NULL,
}

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_HKDF_DERIVE,
    .params = &params,
    .len = sizeof(azihsm_algo_hkdf_params),
};
```

## SP 800-108 KDF Counter Derive

SP 800-108 KDF Counter mode derivation implements the KDF as specified in
[NIST SP 800-108](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf).

|                            |                                                                          |
| -------------------------- | ------------------------------------------------------------------------ |
| **Algorithm ID**           | `AZIHSM_ALGO_ID_KBKDF_COUNTER_DERIVE`                                    |
| **Params**                 | [azihsm_algo_kbdf_counter_params](#azihsm_algo_kbdf_counter_params)      |
| **Required Properties**    | None                                                                     |
| **Contributed Properties** | None                                                                     |
| **Supported Operations**   | [azihsm_key_derive](#azihsm_key_derive)                                  |
| **PKCS#11 Mechanism**      | CKM_SP800_108_COUNTER_KDF                                         &nbsp; |

**Example**

```cpp
struct azihsm_algo_kbdf_counter_params params = {
    .hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA512,
    .label = NULL,
    .context = NULL,
}

struct azihsm_algo algo = {
    .id = AZIHSM_ALGO_ID_KBKDF_COUNTER_DERIVE,
    .params = &params,
    .len = sizeof(azihsm_algo_kbdf_counter_params),
};
```

\pagebreak
