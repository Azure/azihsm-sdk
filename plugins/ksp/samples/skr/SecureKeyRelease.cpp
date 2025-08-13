// SecureKeyRelease.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <Windows.h>
#include <winerror.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <iostream>
#include <chrono>
#include <cstring>
#include "Helper.h"
#include "AttestationManager.h"
#include "MsiManager.h"
#include "SkrManager.h"
#include "ArgumentValidator.h"
#include "KeyImporter.h"
#include "AadTokenManager.h"

using json = nlohmann::json;
#pragma comment(lib, "ncrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

LPCWSTR KSP_NAME = L"Microsoft MCR Key Storage Provider";
LPCWSTR MANTICORE_BUILTIN_UNWRAP_KEY = L"MANTICORE_BUILTIN_UNWRAP_KEY";
LPCWSTR MANTICORE_DEVICE_CERT_CHAIN_PROPERTY = L"MANTICORE_DEVICE_CERT_CHAIN_PROPERTY";

NCRYPT_PROV_HANDLE g_hProvider = 0;

static HRESULT PerformSkrTest(
    VaultType vaultType,
    const std::string &vaultUrl,
    const std::string &keyName,
    KeyType keyType,
    const std::string &keyEncAlg)
{
    HRESULT hr = E_FAIL;
    NCRYPT_KEY_HANDLE hImportKey = NULL; // handle to the built-in import key
    NCRYPT_KEY_HANDLE hTargetKey = NULL; // handle to the MHSM target key
    DWORD keyUsageFlags = 0;

    AttestationManager *attestationManager = NULL;
    MsiManager *msiManager = NULL;
    SkrManager *skrManager = NULL;
    AadTokenManager *aadTokenManager = NULL;

    std::string msiToken, attestationToken, skrResponse;
    std::vector<unsigned char> cipherBinary;
    std::vector<unsigned char> certChainVector;
    std::string base64CertChain;

    DWORD certSize = 0;
    PBYTE pCertChain = NULL;

    DWORD bytesWritten = 0;
    DWORD claimBufferSize;
    PBYTE claimBuffer = NULL;
    NCryptBufferDesc rootOutput{};
    PNCryptBuffer pRootOutBuffer;

    std::vector<unsigned char> claimsVector;
    std::string base64Claims;

    unsigned char reportData[128] = {0};

    // Define the paramBuffers array
    NCryptBuffer paramBuffers[] = {
        {static_cast<ULONG>(sizeof(reportData)), NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE, reportData}};

    // Define the params structure
    NCryptBufferDesc params = {NCRYPTBUFFER_VERSION, _countof(paramBuffers), paramBuffers};

    // Initialize global handle to storage provider
    if (FAILED(hr = NCryptOpenStorageProvider(&g_hProvider, KSP_NAME, 0)))
    {
        printf("Error: Unable to open handle to MCR storage provider.\n\n");
        goto Cleanup;
    }
    printf("Info: Successfully opened handle to MCR storage provider.\n\n");

    if (FAILED(hr = NCryptOpenKey(g_hProvider, &hImportKey, MANTICORE_BUILTIN_UNWRAP_KEY, 0, 0)))
    {
        printf("Error: Unable to open the built-in unwrapping key.\n\n");
        goto Cleanup;
    }
    printf("Info: Successfully opened the built-in unwrapping key.\n\n");

    if (FAILED(hr = NCryptGetProperty(g_hProvider, MANTICORE_DEVICE_CERT_CHAIN_PROPERTY, NULL, 0, &certSize, 0)))
    {
        printf("Error: Unable to retrieve attestation claim.\n\n");
        return 1;
    }

    pCertChain = (PBYTE)HeapAlloc(GetProcessHeap(), 0, certSize);
    if (pCertChain == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        printf("Error: Memory allocation failed for certificate chain buffer: 0x%X\n\n", hr);
        return 1;
    }

    if (FAILED(hr = NCryptGetProperty(g_hProvider, MANTICORE_DEVICE_CERT_CHAIN_PROPERTY, pCertChain, certSize, &certSize, 0)))
    {
        printf("Error: NCryptGetProperty failed.\n\n");
        return 1;
    }
    printf("Info: Successfully retrieved the MCR device cert chain.\n\n");

    // Convert pCertChain to base64 and print
    certChainVector.assign(pCertChain, pCertChain + certSize);
    base64CertChain = binary_to_base64url(certChainVector);
    std::cout << "Base64url Encoded Certificate Chain: " << base64CertChain << std::endl
              << std::endl;

    if (FAILED(hr = NCryptCreateClaim(
                   hImportKey,
                   NULL,
                   0,
                   &params,
                   NULL,
                   0,
                   &bytesWritten,
                   0)))
    {
        wprintf(L"Error: NCryptCreateClaim failed: 0x%X\n", hr);
        goto Cleanup;
    }

    claimBufferSize = bytesWritten;
    claimBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, claimBufferSize);
    if (claimBuffer == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        wprintf(L"Error: Memory allocation failed for claim buffer: 0x%X\n\n", hr);
        goto Cleanup;
    }

    bytesWritten = 0;
    if (FAILED(hr = NCryptCreateClaim(
                   hImportKey,
                   NULL,
                   0,
                   &params,
                   claimBuffer,
                   claimBufferSize,
                   &bytesWritten,
                   0)))
    {
        wprintf(L"Error: NCryptCreateClaim failed: 0x%X\n\n", hr);
        goto Cleanup;
    }
    printf("Info: Successfully created the Attestation Claim.\n\n");

    // Convert claimBuffer to base64 and print
    claimsVector.assign(claimBuffer, claimBuffer + bytesWritten);
    base64Claims = binary_to_base64url(claimsVector);
    std::cout << "Base64url Encoded Attestation Claim: " << base64Claims << std::endl
              << std::endl;

    printf("Success: Claim created successfully. It may be shared with the verifier side.\n\n");

    // Get Attestation token from Mock MAA to perform SKR
    attestationManager = new AttestationManager(base64CertChain, base64Claims);
    attestationToken = attestationManager->GetAttestationToken();
    printf("Attestation Token from Mock MAA: %s\n\n", attestationToken.c_str());
    if (attestationToken.empty())
        goto Cleanup;

    msiManager = new MsiManager();
    msiToken = msiManager->GetMsiToken(vaultType);
    if (msiToken.empty())
        goto Cleanup;
    printf("Auth Token: %s\n\n", msiToken.c_str());

    // Perform secure key release
    skrManager = new SkrManager(msiToken, attestationToken, vaultUrl, keyName, keyEncAlg);
    skrResponse = skrManager->PerformSkr();
    printf("SKR Response from MHSM/AKV: %s\n\n", skrResponse.c_str());
    if (skrResponse.empty())
        goto Cleanup;
    cipherBinary = base64url_to_binary(skrResponse);

    if (FAILED(KeyImporter::ImportPkcs11NCryptRsaKey(g_hProvider, reinterpret_cast<PBYTE>(&cipherBinary[0]), cipherBinary.size(), hImportKey, keyType, keyEncAlg, &hTargetKey)))
    {
        printf("Error: Failed to import SKR response to MCR\n");
        goto Cleanup;
    }

    printf("Success: Securely imported MHSM key to Manticore.\n\n");
    hr = S_OK;

Cleanup:
    if (hImportKey)
    {
        NCryptDeleteKey(hImportKey, NCRYPT_SILENT_FLAG);
    }

    if (hTargetKey)
    {
        NCryptDeleteKey(hTargetKey, NCRYPT_SILENT_FLAG);
    }

    delete attestationManager;
    delete msiManager;
    delete skrManager;
    delete aadTokenManager;

    if (pCertChain)
    {
        HeapFree(GetProcessHeap(), 0, pCertChain);
    }

    if (claimBuffer)
    {
        HeapFree(GetProcessHeap(), 0, claimBuffer);
    }

    return hr;
}

int main(int argc, char *argv[])
{
    printf("Secure Key Release to Manticore - Test started...\n\n");

    if (argc < MIN_ARGS)
    {
        printf("Invalid Arguments. Try SecureKeyRelease.exe <vault type [AKV | MHSM]> <vault URL> "
               "<key name> <key type [RSA_2048 | RSA_3072 | RSA_4096 | ECDSA_P256 | ECDSA_P384 | "
               "ECDSA_P521 | ECDH_P256 | ECDH_P384 | ECDH_P521  | AES_128 | AES_192 | AES_256]> "
               "<key enc alg [CKM_RSA_AES_KEY_WRAP | RSA_AES_KEY_WRAP_256 | RSA_AES_KEY_WRAP_384]>\n");
        return -1;
    }

    VaultType vaultType;
    KeyType keyType;

    if (!ArgumentValidator::ValidateVaultType(argv[1], vaultType) ||
        !ArgumentValidator::ValidateKeyType(argv[4], keyType))
    {
        printf("Invalid vault type or key type specified! Try SecureKeyRelease.exe <vault type [AKV | MHSM]> <vault URL> <key name> <key type [RSA_2048 | RSA_3072 | RSA_4096 | ECDSA_P256 | ECDSA_P384 | ECDSA_P521 | ECDH_P256 | ECDH_P384 | ECDH_P521  | AES_128 | AES_192 |AES_256]> <key enc alg [CKM_RSA_AES_KEY_WRAP | RSA_AES_KEY_WRAP_256 | RSA_AES_KEY_WRAP_384]>\n");
        return -1;
    }

    std::string vaultUrl = argv[2];
    std::string keyName = argv[3];
    std::string keyEncAlg = argv[5];

    if (keyEncAlg != "CKM_RSA_AES_KEY_WRAP" && keyEncAlg != "RSA_AES_KEY_WRAP_256" && keyEncAlg != "RSA_AES_KEY_WRAP_384")
    {
        printf("Invalid Key Encryption Algorithm\n");
        return -1;
    }

    printf("Vault Type: %s\n", vaultType == VaultType::AKV ? "AKV" : "MHSM");
    printf("Vault URL: %s\n", vaultUrl.c_str());
    printf("Key Name: %s\n", keyName.c_str());
    printf("Key Type: %s\n\n", keyType == KeyType::RSA_2048 ? "RSA_2048" : keyType == KeyType::RSA_3072 ? "RSA_3072"
                                                                       : keyType == KeyType::RSA_4096   ? "RSA_4096"
                                                                       : keyType == KeyType::ECDSA_P256 ? "ECDSA_P256"
                                                                       : keyType == KeyType::ECDSA_P384 ? "ECDSA_P384"
                                                                       : keyType == KeyType::ECDSA_P521 ? "ECDSA_P521"
                                                                       : keyType == KeyType::ECDH_P256  ? "ECDH_P256"
                                                                       : keyType == KeyType::ECDH_P384  ? "ECDH_P384"
                                                                       : keyType == KeyType::ECDH_P521  ? "ECDH_P521"
                                                                       : keyType == KeyType::AES_128    ? "AES_128"
                                                                       : keyType == KeyType::AES_192    ? "AES_192"
                                                                                                        : "AES_256");

    if (FAILED(PerformSkrTest(vaultType, vaultUrl, keyName, keyType, keyEncAlg)))
    {
        printf("Secure Key Release Test failed!\n\n");
        return -1;
    }

    printf("Secure Key Release Test complete!\n\n");

    return 0;
}
