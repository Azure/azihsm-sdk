//-------------------------------------------------------------------------------------------------
// <copyright file="KeyImporter.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once
#include <Windows.h>
#include <ncrypt.h>
#include "ArgumentValidator.h"

#define BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB L"PKCS11RsaAesWrapBlob"
#define BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC 0x57504152 // 'RAPW' for RSA-AES-PAD-WRAP (PKCS11-RSA-AES-WRAP)

/**
 * @struct BCRYPT_PKCS11_RSA_AES_WRAP_BLOB
 * @brief Structure representing the PKCS#11 RSA-AES wrap blob.
 */
typedef struct _BCRYPT_PKCS11_RSA_AES_WRAP_BLOB
{
    ULONG dwMagic;        // BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC
    ULONG cbKey;          // Number of bytes in the binary PKCS#11 wrapped key blob
    ULONG cbPaddingAlgId; // Number of bytes in OAEP Padding algorithm per OAEPParams in PKCS#11 specification
    ULONG cbPaddingLabel; // Number of bytes in OAEP Padding label per OAEPParams in PKCS#11 specification
    // UCHAR Key[cbKey];                   -- PKCS#11 binary blob
    // UCHAR PaddingAlgId[cbPaddingAlgId]; -- OAEP Padding information for PKCS#11 unwrapping
    // UCHAR PaddingLabel[cbPaddingLabel]; -- OAEP Padding information for PKCS#11 unwrapping
} BCRYPT_PKCS11_RSA_AES_WRAP_BLOB, *PBCRYPT_PKCS11_RSA_AES_WRAP_BLOB;

/**
 * @class KeyImporter
 * @brief Manages the import of PKCS#11 blob to Manticore
 */
class KeyImporter
{
public:
    /**
     * @brief Imports a PKCS#11 blob to Manticore
     *
     * @param hProvider Handle to the NCrypt provider.
     * @param pbRsaPkcs11 Pointer to the PKCS#11 wrapped key blob.
     * @param cbRsaPkcs11 Size of the PKCS#11 wrapped key blob.
     * @param hImportKey Handle to the import key.
     * @param keyType The type of the key.
     * @param keyEncAlg The key encryption algorithm.
     * @param phKey Pointer to the handle of the imported key.
     * @return SECURITY_STATUS indicating success or failure.
     */
    static SECURITY_STATUS ImportPkcs11NCryptRsaKey(
        IN NCRYPT_PROV_HANDLE hProvider,
        IN PBYTE pbRsaPkcs11,
        IN ULONG cbRsaPkcs11,
        IN NCRYPT_KEY_HANDLE hImportKey,
        IN KeyType keyType,
        IN std::string keyEncAlg,
        _Out_ NCRYPT_KEY_HANDLE *phKey)
    {
        if (!hProvider || !pbRsaPkcs11 || !hImportKey)
        {
            printf("Invalid input parameters.\n");
            return E_INVALIDARG;
        }

        // Get the algorithm ID for the specified key type
        LPCWSTR pszAlgId = GetAlgorithmIdForKeyType(keyType);
        if (!pszAlgId)
        {
            printf("Invalid key type.\n");
            return E_INVALIDARG;
        }

        SECURITY_STATUS Status;
        NCRYPT_KEY_HANDLE hTargetKey = NULL;
        PBYTE pbWrappedBlob = NULL;
        ULONG cbWrappedBlob = 0;
        BCRYPT_PKCS11_RSA_AES_WRAP_BLOB *pWrapped = NULL;
        DWORD keyUsage = NCRYPT_ALLOW_SIGNING_FLAG;

        NCryptBuffer paramBuffers[] = {
            {static_cast<ULONG>(wcslen(pszAlgId) + 1) * sizeof(WCHAR), NCRYPTBUFFER_PKCS_ALG_ID, (PBYTE)(pszAlgId)} //,
        };

        NCryptBufferDesc params = {NCRYPTBUFFER_VERSION, _countof(paramBuffers), paramBuffers};

        LPCWSTR hashAlg = keyEncAlg == "CKM_RSA_AES_KEY_WRAP" ? BCRYPT_SHA1_ALGORITHM : keyEncAlg == "RSA_AES_KEY_WRAP_256" ? BCRYPT_SHA256_ALGORITHM
                                                                                                                            : BCRYPT_SHA384_ALGORITHM;

        // Create blob structure for input
        cbWrappedBlob = sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB) + cbRsaPkcs11 + static_cast<ULONG>(wcslen(hashAlg) + 1) * sizeof(WCHAR);
        pbWrappedBlob = (PBYTE)LocalAlloc(LMEM_FIXED, cbWrappedBlob);

        if (pbWrappedBlob == NULL)
        {
            printf("LocalAlloc(%ld) failed\n", cbWrappedBlob);
            Status = STATUS_NO_MEMORY;
            goto cleanup;
        }

        pWrapped = (BCRYPT_PKCS11_RSA_AES_WRAP_BLOB *)pbWrappedBlob;
        pWrapped->dwMagic = BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC;
        pWrapped->cbKey = cbRsaPkcs11;
        pWrapped->cbPaddingAlgId = static_cast<ULONG>(wcslen(hashAlg) + 1) * sizeof(WCHAR);
        pWrapped->cbPaddingLabel = 0;

        memcpy(pbWrappedBlob + sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB), pbRsaPkcs11, cbRsaPkcs11);
        memcpy(pbWrappedBlob + sizeof(BCRYPT_PKCS11_RSA_AES_WRAP_BLOB) + cbRsaPkcs11,
               (PBYTE)hashAlg,
               static_cast<ULONG>(wcslen(hashAlg) + 1) * sizeof(WCHAR));

        // Import the target key
        Status = NCryptImportKey(
            hProvider,
            hImportKey,
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            &params,
            &hTargetKey,
            pbWrappedBlob,
            cbWrappedBlob,
            NCRYPT_DO_NOT_FINALIZE_FLAG);
        if (FAILED(Status))
        {
            printf("NCryptImportKey failed %08x\n", Status);
            goto cleanup;
        }

        Status = NCryptSetProperty(hTargetKey, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&keyUsage, sizeof(keyUsage), 0);
        if (FAILED(Status))
        {
            printf("NCryptSetProperty failed %08x\n", Status);
            goto cleanup;
        }

        Status = NCryptFinalizeKey(hTargetKey, 0);
        if (FAILED(Status))
        {
            printf("NCryptFinalizeKey failed %08x\n", Status);
            goto cleanup;
        }

        *phKey = hTargetKey;
        hTargetKey = NULL;

    cleanup:
        if (hTargetKey)
        {
            NCryptFreeObject(hTargetKey);
        }
        if (pbWrappedBlob)
        {
            LocalFree(pbWrappedBlob);
        }

        return Status;
    }

private:
    /**
     * @brief Gets the algorithm ID for the specified key type.
     *
     * @param keyType The type of the key.
     * @return LPCWSTR The algorithm ID.
     */
    static LPCWSTR GetAlgorithmIdForKeyType(KeyType keyType)
    {
        switch (keyType)
        {
        case KeyType::RSA_2048:
        case KeyType::RSA_3072:
        case KeyType::RSA_4096:
            return BCRYPT_RSA_ALGORITHM;
        case KeyType::ECDSA_P256:
            return BCRYPT_ECDSA_P256_ALGORITHM;
        case KeyType::ECDSA_P384:
            return BCRYPT_ECDSA_P384_ALGORITHM;
        case KeyType::ECDSA_P521:
            return BCRYPT_ECDSA_P521_ALGORITHM;
        case KeyType::ECDH_P256:
            return BCRYPT_ECDH_P256_ALGORITHM;
        case KeyType::ECDH_P384:
            return BCRYPT_ECDH_P384_ALGORITHM;
        case KeyType::ECDH_P521:
            return BCRYPT_ECDH_P521_ALGORITHM;
        case KeyType::AES_128:
        case KeyType::AES_192:
        case KeyType::AES_256:
            return BCRYPT_AES_ALGORITHM;
        default:
            return nullptr;
        }
    }

    /**
     * @brief Converts the key type to a string representation.
     *
     * @param keyType The type of the key.
     * @return std::string The string representation of the key type.
     */
    static std::string KeyTypeToString(KeyType keyType)
    {
        switch (keyType)
        {
        case KeyType::RSA_2048:
            return "RSA_2048";
        case KeyType::RSA_3072:
            return "RSA_3072";
        case KeyType::RSA_4096:
            return "RSA_4096";
        case KeyType::ECDSA_P256:
            return "ECDSA_P256";
        case KeyType::ECDSA_P384:
            return "ECDSA_P384";
        case KeyType::ECDSA_P521:
            return "ECDSA_P521";
        case KeyType::ECDH_P256:
            return "ECDH_P256";
        case KeyType::ECDH_P384:
            return "ECDH_P384";
        case KeyType::ECDH_P521:
            return "ECDH_P521";
        case KeyType::AES_128:
            return "AES_128";
        case KeyType::AES_192:
            return "AES_192";
        case KeyType::AES_256:
            return "AES_256";
        default:
            return "Unknown";
        }
    }
};