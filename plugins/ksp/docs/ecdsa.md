# Elliptic Curve Digital Signature Algorithm (ECDSA)

ECDSA (Elliptic Curve Digital Signature Algorithm) is a widely used cryptographic algorithm for digital signatures. It leverages elliptic curve mathematics to provide robust security with smaller key sizes compared to algorithms like RSA, making it efficient and secure.

## Key Features Supported by Azure Integrated HSM (AZIHSM) for ECDSA

AZIHSM provides comprehensive support for ECDSA key operations, including:

1. **Key Generation**
   - Supported Curves: P256, P384, P521

2. **Sign and Verify Operations**
   - Perform secure digital signature creation and verification.

3. **Key Attestation**
   - Validate and certify the authenticity of ECDSA keys.

4. **Secure Import of ECDSA Keys**
   - Enable Secure Key Release (SKR) from Azure managed HSM/AKV.

In this document, we will cover how to perform different ECDSA key operations using NCrypt APIs.

## ECDSA Key Generation

To create ECDSA keys in AZIHSM using the NCrypt APIs, follow these steps:

### 1. Sequence of API Calls

The sequence of API calls for ECDSA key generation is:
1. `NCryptCreatePersistedKey()`
2. `NCryptSetProperty()`
3. `NCryptFinalizeKey()`

### 2. NCryptCreatePersistedKey

The `NCryptCreatePersistedKey()` API takes the following parameters:
- `hProvider`: A valid provider handle.
- `pszAlgId`: The cryptographic algorithm identifier - `BCRYPT_ECDSA_ALGORITHM`, `BCRYPT_ECDSA_P256_ALGORITHM`, `BCRYPT_ECDSA_P384_ALGORITHM`, `BCRYPT_ECDSA_P521_ALGORITHM`
- `phKey`: An output handle to the key.

**Important Notes**:
- Named keys are not supported by AZIHSM.
- It is mandatory to pass `NCRYPT_DO_NOT_FINALIZE_FLAG` as part of `dwFlags`, otherwise AZIHSM KSP will reject the key creation call.

```c
SECURITY_STATUS NCryptCreatePersistedKey(
  [in]           NCRYPT_PROV_HANDLE hProvider,
  [out]          NCRYPT_KEY_HANDLE  *phKey,
  [in]           LPCWSTR            pszAlgId,
  [in, optional] LPCWSTR            pszKeyName,
  [in]           DWORD              dwLegacyKeySpec,
  [in]           DWORD              dwFlags
);
```
### 3. NCryptSetProperty
If the cryptographic algorithm ID used in `NCryptCreatePersistedKey()` does not infer the curve type, a `NCryptSetProperty()` call is required to set the Curve Type - `BCRYPT_ECC_CURVE_NISTP256`, `BCRYPT_ECC_CURVE_NISTP384`, `BCRYPT_ECC_CURVE_NISTP521`
```
SECURITY_STATUS NCryptSetProperty(
  [in] NCRYPT_HANDLE hObject,
  [in] LPCWSTR       pszProperty,
  [in] PBYTE         pbInput,
  [in] DWORD         cbInput,
  [in] DWORD         dwFlags
);
```
### 4. NCryptFinalizeKey
Once the Algorithm ID and Curve Type are set, a `NCryptFinalizeKey()` call is required on the key handle. This call actually creates the key in the HSM.
```
SECURITY_STATUS NCryptFinalizeKey(
  [in] NCRYPT_KEY_HANDLE hKey,
  [in] DWORD             dwFlags
);
```

### Example Code

Below is a code example demonstrating the ECDSA key generation process using NCrypt APIs:
```
let mut azihsm_provider: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
let mut azihsm_key: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);

unsafe {
    let result = NCryptOpenStorageProvider(&mut azihsm_provider, AZIHSM_KSP_NAME, 0);
    assert!(result.is_ok());

    let result = NCryptCreatePersistedKey(
        azihsm_provider,
        &mut azihsm_key,
        BCRYPT_ECDSA_ALGORITHM,
        None,
        CERT_KEY_SPEC(0),
        NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
    );
    assert!(result.is_ok());

    let curve_type = std::slice::from_raw_parts(
        BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
        BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
    );
    let result = NCryptSetProperty(
        azihsm_key,
        NCRYPT_ECC_CURVE_NAME_PROPERTY,
        curve_type,
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok());

    let result = NCryptFinalizeKey(azihsm_key, NCRYPT_FLAGS(0));
    assert!(result.is_ok());
}
```

## ECDSA - Sign and Verify Operations

The APIs used for ECDSA sign/verify operations are:
1. `NCryptSignHash()`
2. `NCryptVerifySignature()`

### 1. NCryptSignHash
- The API expects a valid ECDSA key handle and a valid digest value
  - P256 supports signing of digest of length 20, 32
  - P256 supports signing of digest of length 20, 32 and 48
  - P256 supports signing of digest of length 20, 32, 48 and 64
- No padding info or flags are expected for ECDSA sign operation
 
```
SECURITY_STATUS NCryptSignHash(
  [in]           NCRYPT_KEY_HANDLE hKey,
  [in, optional] VOID              *pPaddingInfo,
  [in]           PBYTE             pbHashValue,
  [in]           DWORD             cbHashValue,
  [out]          PBYTE             pbSignature,
  [in]           DWORD             cbSignature,
  [out]          DWORD             *pcbResult,
  [in]           DWORD             dwFlags
);
```

### 2. NCryptVerifySignature
- No padding info or flags are expected for ECDSA verify operation

```
SECURITY_STATUS NCryptVerifySignature(
  [in]           NCRYPT_KEY_HANDLE hKey,
  [in, optional] VOID              *pPaddingInfo,
  [in]           PBYTE             pbHashValue,
  [in]           DWORD             cbHashValue,
  [in]           PBYTE             pbSignature,
  [in]           DWORD             cbSignature,
  [in]           DWORD             dwFlags
);
```

### Example Code

```
let mut azihsm_provider: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    let mut azihsm_key: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);

    unsafe {
        let result = NCryptOpenStorageProvider(&mut azihsm_provider, AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider,
            &mut azihsm_key,
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key,
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key, NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let valid_digest_sizes = [20, 32];
        for &digest_size in &valid_digest_sizes {
            let mut digest = vec![0u8; digest_size];
            rand_bytes(&mut digest).unwrap();
            let mut signature_size = 0u32;
            let result = NCryptSignHash(
                azihsm_key,
                None,
                &digest,
                None,
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
            assert_eq!(signature_size, 64);

            let mut signature = vec![0u8; signature_size as usize];
            let result = NCryptSignHash(
                azihsm_key,
                None,
                &digest,
                Some(&mut signature),
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());

            let result = NCryptVerifySignature(azihsm_key, None, &digest, &signature, NCRYPT_FLAGS(0));
            assert!(result.is_ok());
        }

        let result = NCryptDeleteKey(azihsm_key, NCRYPT_SILENT_FLAG.0);
        assert!(result.is_ok());

        let result = NCryptFreeObject(azihsm_provider);
        assert!(result.is_ok());
    }
```
