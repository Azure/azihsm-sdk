KeyGuard and AziHSM Differences
===============================

You may already be familiar with Windows [NCrypt](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/) API when using KeyGuard or LSASS providers. You may already have workloads that interface with these providers.

When adapting an existing NCrypt workload to work with the AziHSM device, here are some differences to keep in mind.

Use the AziHSM Provider Name
----------------------------

The KeyGuard provider is opened by passing string "Microsoft Platform Crypto Provider" when calling [NCryptOpenStorageProvider](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider).

The AziHSM provider must be opened by passing string "Microsoft Azure Integrated HSM Key Storage Provider" when calling NCryptOpenStorageProvider. This string is defined in [include/AziHSM/AziHSM.h](include/AziHSM/AziHSM.h).

Use these algorithms and key sizes
----------------------------------

AziHSM device does not support the same algorithm set as KeyGuard. AziHSM device also supports a restricted set of key sizes.

The following table lists the algorithm IDs supported by the AziHSM provider, and supported key sizes for each.

| Algorithm ID | Applicable NCrypt API | Key sizes |
| ----- | ----- | ----- |
| BCRYPT_AES_ALGORITHM | NCryptCreatePersistedKey, NCryptImportKey | 128, 192, 256 |
| BCRYPT_RSA_ALGORITHM | NCryptImportKey | 2048, 3072, 4096 |
| BCRYPT_ECDH_ALGORITHM | NCryptCreatePersistedKey, NCryptImportKey | P256, P384, P521 |
| BCRYPT_ECDSA_ALGORITHM | NCryptCreatePersistedKey, NCryptImportKey | P256, P384, P521 |
| BCRYPT_SP800108_CTR_HMAC_ALGORITHM | NCryptDeriveKey | N/A |
| BCRYPT_HKDF_ALGORITHM | NCryptDeriveKey | N/A |


Don't create RSA keys
---------------------

AziHSM device generates a single RSA key by default when initialized. This RSA key is called the built-in unwrap key. It can only be used as the `hImportKey` with [NCryptImportKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey) to unwrap encrypted key data. This RSA key cannot be used to decrypt or sign.

You can get a handle for this key by calling [NCryptOpenKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenkey) with "AZIHSM_BUILTIN_UNWRAP_KEY" as `pszKeyName`. This string is defined in [include/AziHSM/AziHSM.h](include/AziHSM/AziHSM.h).

Outside of the built-in unwrap key, the AziHSM device does not support generating RSA keys. This is because RSA keys are large and computationally difficult to generate. AziHSM is an optimized device with limited storage space and computation.

AziHSM device does support importing RSA keys. You can generate an RSA key locally, then import it into the AziHSM device using NCryptImportKey. The [RSA-IMPORT-ENCRYPT-DECRYPT sample](RSA-IMPORT-ENCRYPT-DECRYPT/README.md) shows how to import an RSA key.

Use PKCS#11 encryption to import keys
-------------------------------------

The AziHSM device only supports importing keys in PKCS#11 encrypted format. This format is specified in the [PKCS#11 specification](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908).

If you would like to import key data that is not encrypted, you can encrypt it using the AziHSM built-in unwrap key, then import the encrypted key. The [RSA-IMPORT-ENCRYPT-DECRYPT sample](RSA-IMPORT-ENCRYPT-DECRYPT/README.md) shows how to encrypt clear key data, so it may be imported into the AziHSM device.


Don't use named keys
--------------------

KeyGuard supports storing a key persistently if the user specifies a key name when calling [NCryptCreatePersistedKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey) or [NCryptImportKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey).

AziHSM provider does not currently support persistent storage. AziHSM provider will return an error if key name is set when creating or importing a key.

All AziHSM keys are ephemeral. This means key data will be released when calling [NCryptFreeObject](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreeobject) on a key handle, or calling NCryptFreeObject on the AziHSM provider handle.

Use ImportKey to get a handle for DeriveKey output
--------------------------------------------------

The AziHSM device supports two Key Derivation Functions: HKDF specified in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), and the Counter-HMAC KDF specified in [SP800-108](https://csrc.nist.gov/pubs/sp/800/108/r1/final). AziHSM provider exposes these functions through the [NCryptDeriveKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptderivekey) function.

However, the AziHSM device does not support returning the output of these functions. The AziHSM device considers KDF output to be secret data that cannot leave the device.

For NCryptDeriveKey, AziHSM device outputs handle data as `pcbResult`. You should pass this handle data to [NCryptImportKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey) with pszBlobType "AzIHsmDerivedKeyImportBlob" to convert the handle data to an `NCRYPT_KEY_HANDLE` object. This string is defined in [include/AziHSM/AziHSM.h](include/AziHSM/AziHSM.h).

Note that the `pcbResult` handle data is context specific. Passing this data to a different AziHSM provider object will result in a failure.

The [ECDH-KDF-AESCBC sample](ECDH-KDF-AESCBC/README.md) shows how to use the `pcbResult` from a KDF as an AES key handle.

Set usage on keys before finalizing
-----------------------------------

The AziHSM device requires key usage is defined at key creation. This means a given key can only be used for one type of operation. In other words, a key can support decrypt or sign, but not both.

The usage can be configured by setting the NCRYPT_KEY_USAGE_PROPERTY on a key before calling [NCryptFinalizeKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfinalizekey). When importing a key, [NCryptImportKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey) must be used with the `NCRYPT_DO_NOT_FINALIZE_FLAG` to set properties before finalizing.

If unset, the AziHSM provider will assume reasonable defaults for most key types. By default, RSA keys support signing. If you are importing an RSA key for decryption, you will need to set the key usage property before finalizing. The [RSA-IMPORT-ENCRYPT-DECRYPT sample](RSA-IMPORT-ENCRYPT-DECRYPT/README.md) shows how to import an RSA key that can be used for decryption.
