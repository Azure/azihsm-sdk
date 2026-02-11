// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "handle/test_creds.hpp"

#ifdef _WIN32
#define NOMINMAX
// clang-format off
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
// clang-format on
#else
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#endif

/// Result of dynamic POTA endorsement generation.
/// Contains a raw r||s signature (96 bytes for P-384) and a DER-encoded
/// SubjectPublicKeyInfo public key.
struct PotaEndorsement
{
    std::vector<uint8_t> signature;
    std::vector<uint8_t> public_key_der;
};

// clang-format off

/// Hardcoded ECC P-384 private key in PKCS#8 DER format for POTA endorsement signing.
static const uint8_t TEST_POTA_PRIVATE_KEY_DER[] = {
    0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01,
    0x01, 0x04, 0x30, 0x17, 0xe9, 0x1c, 0xac, 0xf7, 0xb7, 0x21, 0xd7, 0x75, 0x20, 0x02, 0x07, 0xbc,
    0xaa, 0x94, 0x2c, 0xe3, 0xb5, 0x5b, 0x78, 0x13, 0xcc, 0x8b, 0xde, 0x87, 0x65, 0x6b, 0xe1, 0x7b,
    0xc2, 0xa8, 0xcc, 0x89, 0x33, 0x4e, 0xcd, 0xaa, 0x9d, 0x1d, 0x09, 0xf1, 0xc7, 0x01, 0x1b, 0x64,
    0xeb, 0x78, 0x5b, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0, 0x67,
    0xc2, 0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0, 0xa9, 0x20,
    0xce, 0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9, 0x5f, 0xe5, 0x90,
    0xab, 0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10, 0xd3, 0x17, 0x6e, 0x99,
    0xc8, 0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3, 0xda, 0x12, 0xc7, 0xdc, 0x3a,
    0xee, 0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64, 0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02,
    0x7d, 0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98
};

/// Hardcoded ECC P-384 public key in SubjectPublicKeyInfo DER format.
/// Corresponds to TEST_POTA_PRIVATE_KEY_DER above.
static const uint8_t TEST_POTA_PUBLIC_KEY_DER[] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0, 0x67, 0xc2,
    0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0, 0xa9, 0x20, 0xce,
    0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9, 0x5f, 0xe5, 0x90, 0xab,
    0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10, 0xd3, 0x17, 0x6e, 0x99, 0xc8,
    0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3, 0xda, 0x12, 0xc7, 0xdc, 0x3a, 0xee,
    0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64, 0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02, 0x7d,
    0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98
};

// clang-format on

#ifdef _WIN32

/// Generates a POTA endorsement dynamically using Windows BCrypt/SymCrypt.
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
inline PotaEndorsement generate_pota_endorsement(azihsm_handle part_handle)
{
    // Step 1: Get PID public key DER from partition
    azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_PART_PUB_KEY, nullptr, 0 };
    auto err = azihsm_part_get_prop(part_handle, &prop);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        throw std::runtime_error(
            "Failed to get PID public key size. Error: " + std::to_string(err)
        );
    }
    std::vector<uint8_t> pid_pub_key_der(prop.len);
    prop.val = pid_pub_key_der.data();
    err = azihsm_part_get_prop(part_handle, &prop);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        throw std::runtime_error("Failed to get PID public key. Error: " + std::to_string(err));
    }

    // Step 2: Parse DER SubjectPublicKeyInfo to extract uncompressed point
    const uint8_t *der = pid_pub_key_der.data();
    size_t der_len = pid_pub_key_der.size();

    std::vector<uint8_t> uncompressed_point;
    bool found = false;
    for (size_t i = 0; i + 97 <= der_len; i++)
    {
        if (der[i] == 0x04 && i > 0 && der[i - 1] == 0x00)
        {
            uncompressed_point.assign(der + i, der + i + 97);
            found = true;
            break;
        }
    }
    if (!found)
    {
        throw std::runtime_error("Failed to find uncompressed point in PID public key DER");
    }

    // Step 3: Load hardcoded ECC P-384 private key from DER
    // Parse PKCS#8 DER to extract raw private key d, x, y for BCrypt import.
    // PKCS#8 layout for our key:
    //   SEQUENCE { version=0, AlgorithmIdentifier { ecPublicKey, secp384r1 },
    //              OCTET STRING { SEC1 ECPrivateKey { version=1, d(48), [1] { BIT STRING { pubpoint
    //              } } } } }
    // The private scalar d starts at offset 35, length 48.
    // The public key uncompressed point (0x04 || x || y) starts at offset 88, x at 89, y at 137.
    static constexpr size_t KEY_SIZE = 48; // P-384 coordinate/scalar size
    static constexpr size_t D_OFFSET = 35;
    static constexpr size_t X_OFFSET = 89;
    static constexpr size_t Y_OFFSET = 137;

    // Build BCRYPT_ECCPRIVATE_BLOB: { BCRYPT_ECCKEY_BLOB header, X, Y, d }
    // BCRYPT_ECCKEY_BLOB: dwMagic(4) + cbKey(4) = 8 bytes header
    std::vector<uint8_t> blob(8 + 3 * KEY_SIZE);
    uint32_t magic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
    uint32_t cbKey = KEY_SIZE;
    std::memcpy(blob.data(), &magic, 4);
    std::memcpy(blob.data() + 4, &cbKey, 4);
    std::memcpy(blob.data() + 8, TEST_POTA_PRIVATE_KEY_DER + X_OFFSET, KEY_SIZE);            // X
    std::memcpy(blob.data() + 8 + KEY_SIZE, TEST_POTA_PRIVATE_KEY_DER + Y_OFFSET, KEY_SIZE); // Y
    std::memcpy(
        blob.data() + 8 + 2 * KEY_SIZE,
        TEST_POTA_PRIVATE_KEY_DER + D_OFFSET,
        KEY_SIZE
    ); // d

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P384_ALGORITHM, nullptr, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    }

    BCRYPT_KEY_HANDLE key = nullptr;
    status = BCryptImportKeyPair(
        alg,
        nullptr,
        BCRYPT_ECCPRIVATE_BLOB,
        &key,
        blob.data(),
        static_cast<ULONG>(blob.size()),
        0
    );
    if (status != STATUS_SUCCESS)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptImportKeyPair failed");
    }

    // Step 4: Hash the uncompressed point with SHA-384
    BCRYPT_ALG_HANDLE hash_alg = nullptr;
    status = BCryptOpenAlgorithmProvider(&hash_alg, BCRYPT_SHA384_ALGORITHM, nullptr, 0);
    if (status != STATUS_SUCCESS)
    {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptOpenAlgorithmProvider (SHA384) failed");
    }

    uint8_t hash[48] = {};
    status = BCryptHash(
        hash_alg,
        nullptr,
        0,
        const_cast<uint8_t *>(uncompressed_point.data()),
        static_cast<ULONG>(uncompressed_point.size()),
        hash,
        sizeof(hash)
    );
    BCryptCloseAlgorithmProvider(hash_alg, 0);
    if (status != STATUS_SUCCESS)
    {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptHash failed");
    }

    // Step 5: Sign the hash with ECDSA P-384
    ULONG sig_len = 0;
    status = BCryptSignHash(key, nullptr, hash, sizeof(hash), nullptr, 0, &sig_len, 0);
    if (status != STATUS_SUCCESS)
    {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptSignHash (size query) failed");
    }

    std::vector<uint8_t> signature(sig_len);
    status =
        BCryptSignHash(key, nullptr, hash, sizeof(hash), signature.data(), sig_len, &sig_len, 0);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (status != STATUS_SUCCESS)
    {
        throw std::runtime_error("BCryptSignHash failed");
    }
    signature.resize(sig_len);

    // Step 6: Return hardcoded public key DER
    std::vector<uint8_t> pub_key_der(
        TEST_POTA_PUBLIC_KEY_DER,
        TEST_POTA_PUBLIC_KEY_DER + sizeof(TEST_POTA_PUBLIC_KEY_DER)
    );

    return { std::move(signature), std::move(pub_key_der) };
}

#else // Linux - OpenSSL

/// Generates a POTA endorsement dynamically using OpenSSL.
///
/// 1. Queries the PID public key from the partition via azihsm_part_get_prop
/// 2. Parses the DER SubjectPublicKeyInfo to extract uncompressed point
/// 3. Loads the hardcoded ECC P-384 private key from DER
/// 4. Hashes the uncompressed point with SHA-384
/// 5. Signs the hash with ECDSA P-384 (raw r||s format, 96 bytes)
/// 6. Returns the hardcoded public key DER
///
/// @param part_handle The partition handle (must be opened, before init)
/// @return PotaEndorsement containing signature and public key DER
/// @throws std::runtime_error on failure
inline PotaEndorsement generate_pota_endorsement(azihsm_handle part_handle)
{
    // Step 1: Get PID public key DER from partition
    azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_PART_PUB_KEY, nullptr, 0 };
    auto err = azihsm_part_get_prop(part_handle, &prop);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        throw std::runtime_error(
            "Failed to get PID public key size. Error: " + std::to_string(err)
        );
    }
    std::vector<uint8_t> pid_pub_key_der(prop.len);
    prop.val = pid_pub_key_der.data();
    err = azihsm_part_get_prop(part_handle, &prop);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        throw std::runtime_error("Failed to get PID public key. Error: " + std::to_string(err));
    }

    // Step 2: Parse DER SubjectPublicKeyInfo to extract uncompressed point
    const uint8_t *der = pid_pub_key_der.data();
    size_t der_len = pid_pub_key_der.size();

    std::vector<uint8_t> uncompressed_point;
    bool found = false;
    for (size_t i = 0; i + 97 <= der_len; i++)
    {
        if (der[i] == 0x04 && i > 0 && der[i - 1] == 0x00)
        {
            uncompressed_point.assign(der + i, der + i + 97);
            found = true;
            break;
        }
    }
    if (!found)
    {
        throw std::runtime_error("Failed to find uncompressed point in PID public key DER");
    }

    // Step 3: Load hardcoded ECC P-384 private key from DER
    const uint8_t *key_ptr = TEST_POTA_PRIVATE_KEY_DER;
    EVP_PKEY *pkey =
        d2i_PrivateKey(EVP_PKEY_EC, nullptr, &key_ptr, sizeof(TEST_POTA_PRIVATE_KEY_DER));
    if (pkey == nullptr)
    {
        throw std::runtime_error("d2i_PrivateKey failed to load hardcoded key");
    }

    // Step 4: Hash the uncompressed point with SHA-384
    uint8_t hash[48] = {};
    unsigned int hash_len = 0;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == nullptr)
    {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha384(), nullptr) != 1 ||
        EVP_DigestUpdate(md_ctx, uncompressed_point.data(), uncompressed_point.size()) != 1 ||
        EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1)
    {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("SHA-384 hashing failed");
    }
    EVP_MD_CTX_free(md_ctx);

    // Step 5: Sign the pre-computed hash with ECDSA P-384 using EVP_PKEY_sign
    // (OpenSSL 3.0+ non-deprecated API for signing pre-hashed data).
    // This produces a DER-encoded ECDSA signature, which we convert to raw r||s.
    EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (sign_ctx == nullptr)
    {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_CTX_new (sign) failed");
    }

    if (EVP_PKEY_sign_init(sign_ctx) <= 0)
    {
        EVP_PKEY_CTX_free(sign_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_sign_init failed");
    }

    // Query required signature buffer size
    size_t der_sig_len = 0;
    if (EVP_PKEY_sign(sign_ctx, nullptr, &der_sig_len, hash, hash_len) <= 0)
    {
        EVP_PKEY_CTX_free(sign_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_sign (size query) failed");
    }

    std::vector<uint8_t> der_sig(der_sig_len);
    if (EVP_PKEY_sign(sign_ctx, der_sig.data(), &der_sig_len, hash, hash_len) <= 0)
    {
        EVP_PKEY_CTX_free(sign_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_sign failed");
    }
    der_sig.resize(der_sig_len);
    EVP_PKEY_CTX_free(sign_ctx);
    EVP_PKEY_free(pkey);

    // Convert DER-encoded ECDSA signature to raw r||s (96 bytes)
    const uint8_t *der_sig_ptr = der_sig.data();
    ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(nullptr, &der_sig_ptr, static_cast<long>(der_sig_len));
    if (ecdsa_sig == nullptr)
    {
        throw std::runtime_error("d2i_ECDSA_SIG failed");
    }

    const BIGNUM *r = nullptr;
    const BIGNUM *s = nullptr;
    ECDSA_SIG_get0(ecdsa_sig, &r, &s);

    std::vector<uint8_t> signature(96, 0);
    int r_len = BN_num_bytes(r);
    int s_len = BN_num_bytes(s);
    BN_bn2bin(r, signature.data() + (48 - r_len));
    BN_bn2bin(s, signature.data() + 48 + (48 - s_len));
    ECDSA_SIG_free(ecdsa_sig);

    // Step 6: Return hardcoded public key DER
    std::vector<uint8_t> pub_key_der(
        TEST_POTA_PUBLIC_KEY_DER,
        TEST_POTA_PUBLIC_KEY_DER + sizeof(TEST_POTA_PUBLIC_KEY_DER)
    );

    return { std::move(signature), std::move(pub_key_der) };
}

#endif // _WIN32

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
inline void make_part_init_config(azihsm_handle part_handle, PartInitConfig &config)
{
#ifdef _WIN32
    char *use_tpm = nullptr;
    size_t use_tpm_len = 0;
    _dupenv_s(&use_tpm, &use_tpm_len, "AZIHSM_USE_TPM");
#else
    const char *use_tpm = std::getenv("AZIHSM_USE_TPM");
#endif
    if (use_tpm != nullptr)
    {
        config.backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_TPM;
        config.backup_config.owner_backup_key = nullptr;
        config.pota_endorsement.source = AZIHSM_POTA_ENDORSEMENT_SOURCE_TPM;
        config.pota_endorsement.endorsement = nullptr;
#ifdef _WIN32
        free(use_tpm);
#endif
    }
    else
    {
        config.obk_buf = { const_cast<uint8_t *>(TEST_OBK), sizeof(TEST_OBK) };
        config.backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
        config.backup_config.owner_backup_key = &config.obk_buf;

        config.generated = generate_pota_endorsement(part_handle);
        config.sig_buf = { config.generated.signature.data(),
                           static_cast<uint32_t>(config.generated.signature.size()) };
        config.pubkey_buf = { config.generated.public_key_der.data(),
                              static_cast<uint32_t>(config.generated.public_key_der.size()) };
        config.pota_data = { .signature = &config.sig_buf, .public_key = &config.pubkey_buf };
        config.pota_endorsement.source = AZIHSM_POTA_ENDORSEMENT_SOURCE_CALLER;
        config.pota_endorsement.endorsement = &config.pota_data;
    }
}
