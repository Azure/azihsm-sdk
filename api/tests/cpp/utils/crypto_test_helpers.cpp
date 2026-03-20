// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "crypto_test_helpers.hpp"

#include <memory>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#endif

namespace
{

// Maps AZIHSM curve identifiers to platform-specific (OpenSSL/CNG) curve selectors.
azihsm_status map_curve(
    azihsm_ecc_curve curve,
#if defined(_WIN32)
    const wchar_t *&algorithm_name
#else
    int &curve_nid
#endif
)
{
    switch (curve)
    {
        case AZIHSM_ECC_CURVE_P256:
#if defined(_WIN32)
            algorithm_name = NCRYPT_ECDSA_P256_ALGORITHM;
#else
            curve_nid = NID_X9_62_prime256v1;
#endif
            return AZIHSM_STATUS_SUCCESS;
        case AZIHSM_ECC_CURVE_P384:
#if defined(_WIN32)
            algorithm_name = NCRYPT_ECDSA_P384_ALGORITHM;
#else
            curve_nid = NID_secp384r1;
#endif
            return AZIHSM_STATUS_SUCCESS;
        case AZIHSM_ECC_CURVE_P521:
#if defined(_WIN32)
            algorithm_name = NCRYPT_ECDSA_P521_ALGORITHM;
#else
            curve_nid = NID_secp521r1;
#endif
            return AZIHSM_STATUS_SUCCESS;
        default:
            return AZIHSM_STATUS_INVALID_ARGUMENT;
    }
}

} // namespace

#if defined(_WIN32)

namespace
{

template <typename HandleType>
struct ScopedNcryptHandle
{
    HandleType value = 0;

    ~ScopedNcryptHandle()
    {
        if (value != 0)
        {
            NCryptFreeObject(value);
        }
    }

    HandleType *out()
    {
        return &value;
    }

    HandleType get() const
    {
        return value;
    }
};

// Minimal DER writer helpers (enough for PKCS#8 + ECPrivateKey structures used by tests).
// Encodes DER length octets for short and long forms.
void der_append_len(std::vector<uint8_t> &out, size_t len)
{
    if (len < 0x80)
    {
        out.push_back(static_cast<uint8_t>(len));
        return;
    }

    std::vector<uint8_t> len_bytes;
    while (len > 0)
    {
        len_bytes.push_back(static_cast<uint8_t>(len & 0xFF));
        len >>= 8;
    }

    out.push_back(static_cast<uint8_t>(0x80 | len_bytes.size()));
    for (auto it = len_bytes.rbegin(); it != len_bytes.rend(); ++it)
    {
        out.push_back(*it);
    }
}

// Appends one DER TLV item with the given tag and value bytes.
void der_append_tlv(std::vector<uint8_t> &out, uint8_t tag, const std::vector<uint8_t> &value)
{
    out.push_back(tag);
    der_append_len(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

// Wraps raw content bytes in a DER SEQUENCE.
std::vector<uint8_t> der_wrap_sequence(const std::vector<uint8_t> &value)
{
    std::vector<uint8_t> out;
    der_append_tlv(out, 0x30, value);
    return out;
}

// Returns DER-encoded named-curve OID bytes for the requested AZIHSM ECC curve.
std::vector<uint8_t> curve_oid_der(azihsm_ecc_curve curve)
{
    switch (curve)
    {
        case AZIHSM_ECC_CURVE_P256:
            return { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
        case AZIHSM_ECC_CURVE_P384:
            return { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
        case AZIHSM_ECC_CURVE_P521:
            return { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
        default:
            return {};
    }
}

// Encodes RFC5915 ECPrivateKey wrapped in RFC5208 PrivateKeyInfo (PKCS#8 v1).
// We intentionally encode only fields needed by tests: version, algorithm OIDs,
// and private scalar octet string.
std::vector<uint8_t> encode_pkcs8_ec_private_key(const uint8_t *d, size_t d_len, azihsm_ecc_curve curve)
{
    std::vector<uint8_t> ec_private_content = { 0x02, 0x01, 0x01 };
    std::vector<uint8_t> private_scalar(d, d + d_len);
    der_append_tlv(ec_private_content, 0x04, private_scalar);
    const std::vector<uint8_t> ec_private_der = der_wrap_sequence(ec_private_content);

    std::vector<uint8_t> algorithm_id_content = {
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
    };
    const auto curve_oid = curve_oid_der(curve);
    algorithm_id_content.insert(algorithm_id_content.end(), curve_oid.begin(), curve_oid.end());
    const std::vector<uint8_t> algorithm_id_der = der_wrap_sequence(algorithm_id_content);

    std::vector<uint8_t> pkcs8_content = { 0x02, 0x01, 0x00 };
    pkcs8_content.insert(pkcs8_content.end(), algorithm_id_der.begin(), algorithm_id_der.end());
    der_append_tlv(pkcs8_content, 0x04, ec_private_der);

    return der_wrap_sequence(pkcs8_content);
}

} // namespace

namespace crypto_test_helpers
{

// Generates ECC private key material as PKCS#8 DER for unwrap/import tests.
azihsm_status generate_ecc_pkcs8_der(azihsm_ecc_curve curve, std::vector<uint8_t> &der)
{
    auto fail = [&]() -> azihsm_status {
        der.clear();
        return AZIHSM_STATUS_INTERNAL_ERROR;
    };

    // Resolve the requested curve to the CNG algorithm identifier.
    const wchar_t *algorithm_name = nullptr;
    const auto curve_status = map_curve(curve, algorithm_name);
    if (curve_status != AZIHSM_STATUS_SUCCESS)
    {
        der.clear();
        return curve_status;
    }

    // Create an ephemeral software key via the Microsoft Key Storage Provider.
    ScopedNcryptHandle<NCRYPT_PROV_HANDLE> provider_handle;
    ScopedNcryptHandle<NCRYPT_KEY_HANDLE> key_handle;

    SECURITY_STATUS sec_status = NCryptOpenStorageProvider(
        provider_handle.out(),
        MS_KEY_STORAGE_PROVIDER,
        0
    );
    if (sec_status != ERROR_SUCCESS)
    {
        return fail();
    }

    sec_status = NCryptCreatePersistedKey(
        provider_handle.get(),
        key_handle.out(),
        algorithm_name,
        nullptr,
        0,
        0
    );
    if (sec_status != ERROR_SUCCESS)
    {
        return fail();
    }

    // Ensure plaintext PKCS#8 export is permitted for test-generated keys.
    DWORD export_policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    sec_status = NCryptSetProperty(
        key_handle.get(),
        NCRYPT_EXPORT_POLICY_PROPERTY,
        reinterpret_cast<PBYTE>(&export_policy),
        static_cast<DWORD>(sizeof(export_policy)),
        0
    );
    if (sec_status != ERROR_SUCCESS)
    {
        return fail();
    }

    sec_status = NCryptFinalizeKey(key_handle.get(), 0);
    if (sec_status != ERROR_SUCCESS)
    {
        return fail();
    }

    // Export as raw CNG blob and re-encode to PKCS#8 ourselves.
    // This keeps DER encoding stable/portable for simulator import tests.
    DWORD blob_len = 0;
    sec_status = NCryptExportKey(
        key_handle.get(),
        0,
        BCRYPT_ECCPRIVATE_BLOB,
        nullptr,
        nullptr,
        0,
        &blob_len,
        0
    );
    if (sec_status != ERROR_SUCCESS || blob_len == 0)
    {
        return fail();
    }

    std::vector<uint8_t> blob(static_cast<size_t>(blob_len));
    sec_status = NCryptExportKey(
        key_handle.get(),
        0,
        BCRYPT_ECCPRIVATE_BLOB,
        nullptr,
        blob.data(),
        blob_len,
        &blob_len,
        0
    );

    if (sec_status != ERROR_SUCCESS || blob_len < sizeof(BCRYPT_ECCKEY_BLOB))
    {
        return fail();
    }

    const auto *hdr = reinterpret_cast<const BCRYPT_ECCKEY_BLOB *>(blob.data());
    const size_t key_bytes = static_cast<size_t>(hdr->cbKey);
    const size_t header_size = sizeof(BCRYPT_ECCKEY_BLOB);
    const size_t required_len = header_size + (3 * key_bytes);
    if (blob.size() < required_len)
    {
        der.clear();
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // BCRYPT_ECCPRIVATE_BLOB layout: header | X | Y | d.
    const uint8_t *d = blob.data() + header_size + (2 * key_bytes);
    der = encode_pkcs8_ec_private_key(d, key_bytes, curve);
    if (der.empty())
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    return AZIHSM_STATUS_SUCCESS;
}

} // namespace crypto_test_helpers

#else

namespace crypto_test_helpers
{

// Generates ECC private key material as PKCS#8 DER for unwrap/import tests.
azihsm_status generate_ecc_pkcs8_der(azihsm_ecc_curve curve, std::vector<uint8_t> &der)
{
    // Resolve the requested curve to an OpenSSL curve NID.
    int curve_nid = 0;
    const auto curve_status = map_curve(curve, curve_nid);
    if (curve_status != AZIHSM_STATUS_SUCCESS)
    {
        der.clear();
        return curve_status;
    }

    // Build an EC keygen context for the selected curve.
    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using Pkcs8InfoPtr =
        std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)>;

    EvpPkeyCtxPtr keygen_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &EVP_PKEY_CTX_free);
    if (keygen_ctx == nullptr)
    {
        der.clear();
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Initialize key generation, bind curve parameters, and generate key material.
    if (EVP_PKEY_keygen_init(keygen_ctx.get()) <= 0)
    {
        der.clear();
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keygen_ctx.get(), curve_nid) <= 0)
    {
        der.clear();
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    EVP_PKEY *private_key_raw = nullptr;
    if (EVP_PKEY_keygen(keygen_ctx.get(), &private_key_raw) <= 0 || private_key_raw == nullptr)
    {
        der.clear();
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    EvpPkeyPtr private_key(private_key_raw, &EVP_PKEY_free);

    // Convert generated key into PKCS#8 and DER-encode into caller buffer.
    Pkcs8InfoPtr pkcs8_info(EVP_PKEY2PKCS8(private_key.get()), &PKCS8_PRIV_KEY_INFO_free);
    if (pkcs8_info == nullptr)
    {
        der.clear();
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    const int der_len = i2d_PKCS8_PRIV_KEY_INFO(pkcs8_info.get(), nullptr);
    if (der_len <= 0)
    {
        der.clear();
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    der.resize(static_cast<size_t>(der_len));
    unsigned char *write_ptr = der.data();
    const int written = i2d_PKCS8_PRIV_KEY_INFO(pkcs8_info.get(), &write_ptr);
    if (written != der_len)
    {
        der.clear();
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    return AZIHSM_STATUS_SUCCESS;
}

} // namespace crypto_test_helpers

#endif
