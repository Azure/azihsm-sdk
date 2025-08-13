# RSA Support in Azure Integrated HSM (AZIHSM) KSP

## Introduction

This document describes the technical implementation and feature support for RSA
in AZIHSM Key Storage Provider (AZIHSM-KSP). It covers the proper usage of the
NCrypt API to use RSA on AZIHSM-KSP.

## Overview

RSA (Rivest-Shamir-Adleman) is a public-key cryptographic system commonly used
for encrypted communication between two parties. Each party has a pair of keys:

* A private key (to be kept secret)
* A public key (to be shared with publicly)

Messages encrypted with the public key can only be decrypted by the private key.

AZIHSM-KSP supports RSA encryption (`NCryptEncrypt()`), decryption
(`NCryptDecrypt()`), signing (`NCryptSignHash()`), and signature verification
(`NCryptVerifySignature()`).

## NCrypt API Usage Targeting RSA

### Importing an RSA Key

AZIHSM-KSP does not support the generation of RSA keys; instead, RSA keys must
be imported via `NCryptImportKey()`. To import an RSA private key into
AZIHSM-KSP, the programmer must follow these steps:

1. Acquire or externally generate the raw bytes of an RSA private key. (This is
   the key you want to import into AZIHSM-KSP.)
    * (We'll call this: `your_rsa_priv_key`)
2. Acquire or externally generate an AES key.
    * (We'll call this: `your_aes_key`)
3. Open a reference to the AZIHSM-KSP built-in unwrapping key via
   `NCryptOpenKey`.
    * Export the built-in unwrapping key's contents (an RSA public key) via
      `NCryptExportKey()`, so it can be used with third-party/external crypto
      libraries/utilities.
    * (We'll call this: `builtin_unwrap_key`)
4. Create an NCrypt-compatible AES/RSA blob.
    1. Use the AES key (`your_aes_key`) to encrypt your RSA private key
       (`your_rsa_priv_key`) into ciphertext `your_rsa_priv_key_CIPHERTEXT`.
    2. Use the built-in unwrapping key (`builtin_unwrap_key`) to encrypt your
       AES key (`your_aes_key`) into ciphertext `your_aes_key_CIPHERTEXT`.
    3. Create the appropriate NCrypt blob structure to describe the key you are
       importing. (Such as: `BCRYPT_PKCS11_RSA_AES_WRAP_BLOB`).
        * (We'll call this: `blob_struct`)
    4. Allocate a string that contains the appropriate NCrypt-compatible hash
       algorithm ID. (Such as: `NCRYPT_SHA256_ALGORITHM`)
        * (We'll call this: `hash_alg_id`)
    5. Concatenate all of the above into a single buffer in this order:
        1. `blob_struct`
        2. `your_aes_key_CIPHERTEXT`
        3. `your_rsa_priv_key_CIPHERTEXT`
        4. `hash_alg_id`
5. Pack the blob into an `NCryptBuffer` object, stored within a
   `NCryptBufferDesc` object, and pass it into `NCryptImportKey()` to import the
   key into AZIHSM-KSP.

Each of these steps is described below.

#### Steps 1-2 - Acquiring Keys

These steps are left up to the programmer. In one way or another, acquire the
bytes that comprise an RSA private key (RSA 2k, RSA 3k, or RSA 4k), and acquire
the bytes that comprise an AES key. This can be done using other crypto
libraries, such as [OpenSSL](https://docs.openssl.org/).

<details>
<summary>(Click here - RSA example)</summary>

Below is an example of generating an RSA key via OpenSSL in C++:

```cpp
// --------------- Part 1 - Generating the RSA Key in OpenSSL --------------- //
EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
if (key_ctx == NULL)
{
    // ERROR - Failed to create key context in OpenSSL
    return 1;
}

// initialize the key context for key generation
if (EVP_PKEY_keygen_init(key_ctx) <= 0)
{
    // ERROR - Failed to initialize key context for key generation in OpenSSL
    EVP_PKEY_CTX_free(key_ctx);
    return 2;
}

// set the number of bits for the RSA key
if (EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, bits) <= 0)
{
    // ERROR - Failed to set key context RSA bits in OpenSSL
    EVP_PKEY_CTX_free(key_ctx);
    return 3;
}

// generate the key
EVP_PKEY* key = NULL;
if (EVP_PKEY_generate(key_ctx, &key) <= 0)
{
    // ERROR - Failed to generated RSA key in OpenSSL
    EVP_PKEY_CTX_free(key_ctx);
    return 4;
}

// --------------- Part 2 - Dumping the Key Bytes to a Buffer --------------- //
void* privkey = NULL;
size_t privkey_len = 0;

// create a BIO buffer to store the dumped key contents
BIO* bio = BIO_new(BIO_s_mem());
if (bio == NULL)
{
    // ERROR - Failed to initialize BIO buffer in OpenSSL
    EVP_PKEY_free(pkey);
    return 5;
}

// dump the private key's contents into the BIO buffer
int dump_result = i2d_PKCS8PrivateKey_bio(
    bio,
    pkey,
    NULL,
    NULL,
    0,
    NULL,
    NULL
);
if (dump_result == 0)
{
    // ERROR - Failed to dump RSA private key bytes to BIO buffer
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return 6;
}

// retrieve the number of bytes in the BIO buffer
privkey_len = BIO_ctrl_pending(bio);

// allocate a new buffer to store the BIO bytes
privkey = malloc(privkey_len * sizeof(BYTE));
if (privkey == NULL)
{
    // ERROR - Failed to allocate memory to store the RSA private key bytes
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return 7;
}

// read all bytes from the BIO into the buffer
if (BIO_read(bio, privkey, privkey_len) == 0)
{
    // ERROR - Failed to read RSA private key bytes from BIO buffer
    free(privkey);
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return 8;
}
BIO_free(bio);
```

</details>

#### Step 3 - Opening the Built-In Unwrapping Key

Use `NCryptOpenKey()` to open a handle to the AZIHSM unwrapping key. Use
`NCryptExportKey()` to export the key's bytes to a buffer, in order to use it
in later steps.

<details>
<summary>(Click here)</summary>

To open the key handle:

```cpp
// C++

NCRYPT_KEY_HANDLE unwrap_key = 0;
int status = NCryptOpenKey(
    provider_handle,
    &unwrap_key,
    AZIHSM_BUILTIN_UNWRAP_KEY,
    0,
    0
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}
```

To export the key's bytes:

```cpp
// C++

DWORD public_key_len_max = 600;
DWORD public_key_len = 0;
BYTE* public_key = (BYTE*) malloc(public_key_len_max * sizeof(BYTE));
// ...
status = NCryptExportKey(
    unwrap_key,
    NULL,
    NCRYPT_OPAQUETRANSPORT_BLOB,
    NULL,
    public_key,
    public_key_len_max,
    &public_key_len,
    0
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}
```

</details>

#### Step 4 - Create NCrypt-Compatible AES/RSA Blob

##### Step 4.1 - Encrypt your RSA Private Key with your AES Key

This step is left up to the programmer. Third-party crypto libraries, such as
OpenSSL, provide functionality to do this. Encrypt the RSA private key and
store the ciphertext in a buffer.

<details>
<summary>(Click here - OpenSSL example)</summary>

Below is an example using OpenSSL in C++.

```cpp
// Takes in AES cipher and AES cipher context objects and encrypts the given
// data (`data`, `data_len`), storing the result in a heap-allocated buffer
// which is stored in `*result` and `*result_len`.
//
// The AES cipher context object must already be initialized for encryption
// (i.e. `EVP_EncryptInit()` must have already been called on
// `aes_cipher_ctx`).
int ossl_encrypt_aes256(EVP_CIPHER* aes_cipher,
                        EVP_CIPHER_CTX* aes_cipher_ctx,
                        BYTE* data,
                        size_t data_len,
                        BYTE** result,
                        size_t* result_len)
{
    // first, determine the number of bytes we'll need to allocate to hold the
    // resulting ciphertext
    size_t padding_len = 8 - (data_len % 8);
    size_t out_len_max = data_len +
                         padding_len +
                         (EVP_CIPHER_get_block_size(aes_cipher) * 2);
    size_t out_len = 0;

    // next, allocate a buffer to store the result
    BYTE* out = (BYTE*) malloc(out_len_max * sizeof(BYTE));
    if (out == NULL)
    {
        // ERROR - Failed to allocate bytes for AES encryption
        return 1;
    }
    
    // update the cipher context with the plaintext data
    int update_len = 0;
    int update_status = EVP_CipherUpdate(
        aes_cipher_ctx,
        out, 
        &update_len,
        data,
        data_len
    );
    if (update_status == 0)
    {
        // ERROR - Failed to update AES cipher context with data
        free(out);
        return 2;
    }
    out_len += update_len;

    // finalize the cipher context
    update_status = EVP_CipherFinal(
        aes_cipher_ctx,
        out + out_len,
        &update_len
    );
    if (update_status == 0)
    {
        // ERROR - Failed to finalize AES cipher context
        free(out);
        return 3;
    }
    out_len += update_len;
    
    // store the output in the return pointers
    *result = out;
    *result_len = out_len;
    return 0;
}
```

</details>

##### Step 4.2 - Encrypt your AES Key with the Built-In Unwrapping Key

This step is left up to the programmer. Third-party crypto libraries, such as
OpenSSL, provide functionality to do this. Encrypt the AES key with the public
key extracted from the AZIHSM built-in unwrapping key, and store the ciphertext
in a buffer.

<details>
<summary>(Click here - OpenSSL example)</summary>

Below is an example using OpenSSL in C++.

```cpp
// Encrypts the provided data with an RSA key, via a `EVP_PKEY_CTX` object that
// is already initialized to hold an RSA key.
//
// The `EVP_PKEY_CTX` must have been already initialized for encryption (i.e.
// `EVP_PKEY_encrypt_init()` must have already been called).
int ossl_encrypt_rsa(EVP_PKEY_CTX* pkey_ctx,
                     BYTE* data,
                     size_t data_len,
                     BYTE** result,
                     size_t* result_len)
{
    // determine the length of the data we'll be receiving from the
    // encryption operation
    size_t out_len = 0;
    if (EVP_PKEY_encrypt(pkey_ctx, NULL, &out_len, data, data_len) <= 0)
    {
        // ERROR - Failed to determine ciphertext length in OpenSSL
        return 1;
    }

    // allocate a buffer to store the encrypted ciphertext
    BYTE* out = (BYTE*) malloc(out_len * sizeof(BYTE));
    if (out == NULL)
    {
        // ERROR - Failed to allocate bytes for RSA encryption ciphertext
        free(out);
        return 2;
    }

    // encrypt the plaintext
    if (EVP_PKEY_encrypt(pkey_ctx, out, &out_len, data, data_len) <= 0)
    {
        // ERROR - Failed to encrypt data with RSA key in OpenSSL
        free(out);
        return 3;
    }
    
    // set return pointers and return
    *result = out;
    *result_len = out_len;
    return 0;
}
```

</details>

##### Step 4.3 - Creating the NCrypt Blob Structure

In this step, you must combine the two encrypted keys, an NCrypt blob struct,
and an NCrypt hash algorithm ID string into a single contiguous chunk of
memory.

<details>
<summary>(Click here)</summary>

Start by determining the number of bytes needed for the chunk, and allocating
memory.

```cpp
// C++

// NOTE: these code snippets assume you have your encrypted keys stored in
// these variables:
void* your_rsa_priv_key_CIPHERTEXT = /* (pointer to memory) */
void* your_rsa_priv_key_CIPHERTEXT_len = /* (number of allocated bytes) */
void* your_aes_key_CIPHERTEXT = /* (pointer to memory) */
void* your_aes_key_CIPHERTEXT_len = /* (number of allocated bytes) */

// NOTE: this code assumes your AES key is 256-bit, and that you are using
// SHA-256 for the hashing algorithm.
LPCWSTR hash_alg = NCRYPT_SHA256_ALGORITHM;
size_t hash_alg_len = static_cast<ULONG>(wcslen(hash_alg) + 1) * sizeof(WCHAR);

// Compute the total number of bytes required to hold *everything*, and
// allocate memory.
size_t blob_data_len = sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB) +
                       your_rsa_priv_key_CIPHERTEXT_len +
                       your_aes_key_CIPHERTEXT_len +
                       hash_alg_len;
BYTE* blob_data = (BYTE*) malloc(blob_data_len * sizeof(BYTE));
```

Next, grab a pointer to the beginning of your `blob_data` buffer, and interpret
it as a `BCRYPT_PKCS11_RSA_AES_WRAP_BLOB` struct. Initialize its fields
appropriately:

```cpp
// C++

BCRYPT_PKCS11_RSA_AES_WRAP_BLOB* blob = (BCRYPT_PKCS11_RSA_AES_WRAP_BLOB*) blob_data;
blob->dwMagic = BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC;
blob->cbKey = (DWORD) wrapped_data_len;
blob->cbPaddingAlgId = hash_alg_len;
blob->cbPaddingLabel = 0;
```

Next, copy the encrypted AES key, followed by the encrypted RSA private key,
into the blob data, stored immediately after the NCrypt blob object:

```cpp
// C++

// Copy encrypted AES key contents:
memcpy(
    blob_data + sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB),
    your_aes_key_CIPHERTEXT,
    your_aes_key_CIPHERTEXT_len
);

// Copy encrypted RSA private key contents:
memcpy(
    blob_data + sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB) + your_aes_key_CIPHERTEXT_len
    your_rsa_priv_key_CIPHERTEXT,
    your_rsa_priv_key_CIPHERTEXT_len
);
```

Finally, copy the hashing algoritm ID string to the very end of the buffer:

```cpp
// C++

memcpy(
    blob_data + sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB) + your_aes_key_CIPHERTEXT_len + your_rsa_priv_key_CIPHERTEXT_len
    (PBYTE) hash_alg,
    hash_alg_len
);
```

With that, the blob data is ready to go.

</details>

#### Step 5 - Create NCrypt Buffers and Invoke `NCryptImportKey()`

The final step before invoking `NCryptImportKey()` is to create an
`NCryptBuffer` object and store it in an `NCryptBufferDesc` object. This is the
object that we'll pass into `NCryptImportKey()`.

<details>
<summary>(Click here)</summary>

```cpp
// C++

// Set up an`NCryptBuffer` object to specify the algorithm of the key we're
// about to import, as well as describe what kind of blob data we are providing.
const DWORD param_buffers_len = 1;
NCryptBuffer param_buffers[param_buffers_len];
param_buffers[0].cbBuffer = static_cast<ULONG>(wcslen(BCRYPT_RSA_ALGORITHM) + 1) * sizeof(WCHAR);
param_buffers[0].BufferType = NCRYPTBUFFER_PKCS_ALG_ID;
param_buffers[0].pvBuffer = (PVOID) BCRYPT_RSA_ALGORITHM;

// Pack the buffer into an `NCryptBufferDesc` object, which we'll pass into
// `NCryptImportKey`.
NCryptBufferDesc params;
params.ulVersion = NCRYPTBUFFER_VERSION;
params.cBuffers = param_buffers_len;
params.pBuffers = param_buffers;
```

Finally, invoke `NCryptImportKey()` to import your RSA private key:

```cpp
// C++

status = NCryptImportKey(
    provider_handle,
    unwrap_key,
    BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
    &params,
    key,
    (PBYTE) blob_data,
    (DWORD) blob_data_len,
    NCRYPT_DO_NOT_FINALIZE_FLAG
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}
```

</details>

#### Step 6 - Set Key Usage and Other Properties

After calling `NCryptImportKey()` and before calling `NCryptFinalizeKey()`, you
must set the key usage property. You can also set other properties, such as
choosing if you would like the key to import with CRT (Chinese Remainder
Theorem) enabled.

##### Setting Key Usage

AZIHSM requires that imported RSA keys specify a specific usage
(encryption/decryption or signing). A single key cannot be used for
*everything*, so the intended use-case must be specified.

<details>
<summary>(Click here)</summary>

To set the key usage, invoke `NCryptSetProperty()` with the
`NCRYPT_KEY_USAGE_PROPERTY` field, on the imported key's handle. See
[this page](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers)
for all possible key usage settings.

```cpp
// C++

// (after `NCryptImportKey()`)

int usage_flag = NCRYPT_ALLOW_DECRYPT_FLAG;
int status = NCryptSetProperty(
    key,
    NCRYPT_KEY_USAGE_PROPERTY,
    (PBYTE) &usage_flag,
    sizeof(DWORD),
    0
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}

// (before `NCryptFinalizeKey()`)
```
</details>

##### Toggling RSA-CRT

By default, RSA keys imported to AZIHSM are imported with CRT (Chinese
Remainder Theorem) **enabled**. CRT is an optimization of RSA that precomputes
extra values from the RSA key's prime factors/exponentiation. It enables faster
crypto operations with the key, but comes at the cost of requiring more bytes
to store. AZIHSM defines a custom property for RSA keys that can be set to
enable or disable CRT during import.

<details>
<summary>(Click here)</summary>

If you wish to enable or disable CRT for the RSA key you're importing, set the
custom AZIHSM key property as seen below:

```cpp
// C++

// (after `NCryptImportKey()`)

LPCWSTR AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED = L"RsaCrtEnabled";

// The custom property accepts a 32-bit unsinged integer.
//
// * Zero indicates that CRT should *not* be enabled.
// * Non-zero indicates that CRT *should* be enabled (the default).
DWORD enable_crt = 0; // <-- disable CRT for this key

int status = NCryptSetProperty(
    key,
    AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED,
    (PBYTE) &enable_crt,
    sizeof(DWORD),
    0
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}

// (before `NCryptFinalizeKey()`)
```

</details>

#### Step 7 - Finalize the Key Import

The *absolute last step* of importing an RSA key into AZIHSM via NCrypt is to
invoke `NCryptFinalizeKey()`.

<details>
<summary>(Click here)</summary>

```cpp
// C++
int status = NCryptFinalizeKey(key, 0);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}
```

</details>

### Encryption

Invoke `NCryptEncrypt()` with an RSA key handle to encrypt data. See below for
an example.

<details>
<summary>(Click here)</summary>

```cpp
// C++

// NOTE: this assumes the plaintext you wish to encrypt is stored in these
// variables:
BYTE* plainText = /* (pointer to memory) */
DWORD plainTextSize = /* (number of bytes allocated) */

// Set up variables to hold the ciphertext
BYTE* cipherText = NULL;
DWORD cipherTextSize = 0;

// Create a random byte array to use for OAEP padding:
const int paddingSize = 32;
BYTE padding[paddingSize];
// (You should fill the `padding` array with random bytes.)

// Create an NCrypt OEAP padding info struct.
BCRYPT_OAEP_PADDING_INFO pinfo;
pinfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
pinfo.pbLabel = padding;
pinfo.cbLabel = paddingSize;

// Call `NCryptEncrypt()` once, to determine the number of bytes we need to
// allocate to store the ciphertext.
int status = NCryptEncrypt(
    rsa_key_handle,
    plainText,
    plainTextSize,
    &pinfo,
    NULL,
    0,
    &cipherTextSize,
    NCRYPT_PAD_OAEP_FLAG
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}

// Allocate a buffer of the appropriate size to store the ciphertext.
cipherText = malloc(cipherTextSize * sizeof(BYTE));
if (cipherText == NULL)
{
    // ERROR - clean up resources and return
    return 99;
}

// Call `NCryptEncrypt()` a *second* time. This time, we pass in a pointer to
// the buffer at which the ciphertext should be stored. The encryption will
// occur and the memory pointed at by `cipherText` will be updated to store the
// result.
status = NCryptEncrypt(
    rsa_key_handle,
    plainText,
    plainTextSize,
    &pinfo,
    cipherText,
    cipherTextSize,
    &cipherTextSize,
    NCRYPT_PAD_OAEP_FLAG
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}
```

</details>

### Decryption

Invoke `NCryptDecrypt()` with an RSA key handle to decrypt data. See below for
an example.

<details>
<summary>(Click here)</summary>

```cpp
// C++

// NOTE: this assumes the ciphertext you wish to decrypt is stored in these
// variables:
BYTE* cipherText = /* (pointer to memory) */
DWORD cipherTextSize = /* (number of bytes allocated) */

// Set up variables to hold the decrypted plaintext
BYTE* decrypted = NULL;
DWORD decryptedSize = 0;

// Create a random byte array to use for OAEP padding:
const int paddingSize = 32;
BYTE padding[paddingSize];
// (You should fill the `padding` array with random bytes.)

// Create an NCrypt OEAP padding info struct.
BCRYPT_OAEP_PADDING_INFO pinfo;
pinfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
pinfo.pbLabel = padding;
pinfo.cbLabel = paddingSize;

// Call `NCryptDecrypt()` once, to determine the number of bytes we need to
// allocate to store the plaintext.
int status = NCryptDecrypt(
    rsa_key_handle,
    cipherText,
    cipherTextSize,
    &pinfo,
    NULL,
    0,
    &decryptedSize,
    NCRYPT_PAD_OAEP_FLAG
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}

// Allocate a buffer of the appropriate size to store the plaintext.
decrypted = malloc(decryptedSize * sizeof(BYTE));
if (decrypted == NULL)
{
    // ERROR - clean up resources and return
    return 99;
}

// Call `NCryptDecrypt()` a *second* time. This time, we pass in a pointer to
// the buffer at which the plaintext should be stored. The decryption will
// occur and the memory pointed at by `decrypted` will be updated to store the
// result.
status = NCryptDecrypt(
    rsa_key_handle,
    cipherText,
    cipherTextSize,
    &pinfo,
    decrypted,
    decryptedSize,
    &decryptedSize,
    NCRYPT_PAD_OAEP_FLAG
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}
```

</details>

### Signing

Invoke `NCryptSignHash()` with an RSA key handle to sign data. See below for an
example.

<details>
<summary>(Click here)</summary>

```cpp
// C++

// NOTE: this assumes you have your hashed data stored in these variables:
BYTE* hash = /* (pointer to memory) */
int hashSize = /* (number of bytes allocated) */

// Create a padding info struct to pass into `NCryptSignHash`. (NOTE: this
// assumes you are using SHA-256.)
BCRYPT_PSS_PADDING_INFO pinfo;
pinfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
pinfo.cbSalt = 32;

// Call `NCryptSignHash` once, to retrieve the number of bytes required to hold
// the signature.
DWORD sigSize = 0;
int status = NCryptSignHash(
    rsa_key_handle,
    &pinfo,
    hash,
    hashSize,
    NULL,
    0,
    &sigSize,
    BCRYPT_PAD_PSS
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}
 
// Allocate a buffer of the appropriate size to store the signature.
BYTE* sig = malloc(sigSize * sizeof(BYTE));
if (sig == NULL)
{
    // ERROR - clean up resources and return
    return 99;
}

// Call `NCryptSignHash()` a *second* time. This time, we pass in a pointer to
// the buffer at which the signature should be stored. The signing will occur
// and the memory pointed at by `sig` will be updated to store the result.
status = NCryptSignHash(
    rsa_key_handle,
    &pinfo,
    hash,
    hashSize,
    sig,
    sigSize,
    &sigSize,
    BCRYPT_PAD_PSS
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}
```

</details>

### Verifying Signatures

Invoke `NCryptVerifySignature()` with an RSA key handle to verify a
previously-generated signature. See below for an example.

<details>
<summary>(Click here)</summary>

```cpp
// C++

// NOTE: this assumes you have your hashed data (the same hashed data you used
// to generate the signature) stored in these variables:
BYTE* hash = /* (pointer to memory) */
int hashSize = /* (number of bytes allocated) */

// NOTE: this assumes you have your signature stored in these variables:
BYTE* signature = /* (pointer to memory) */
int signatureSize = /* (number of bytes allocated) */

// NOTE: this assumes you already have a padding info struct initialized. See
// the above `NCryptSignHash` code snippet for an example.
BCRYPT_PSS_PADDING_INFO pinfo; /* (this must be initialized) */

// Call `NCryptVerifySignature` a single time to verify the signature.
DWORD sigSize = 0;
int status = NCryptVerifySignature(
    rsa_key_handle,
    &pinfo,
    hash,
    hashSize,
    signature,
    signatureSize,
    BCRYPT_PAD_PSS
);
if (status != ERROR_SUCCESS)
{
    // ERROR - clean up resources and return
    return status;
}
```

</details>

