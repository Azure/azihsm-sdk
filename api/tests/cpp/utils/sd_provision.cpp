// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "sd_provision.hpp"

#if defined(AZIHSM_FEATURE_EMU)

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#ifdef _WIN32
#define NOMINMAX
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#else
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#endif

namespace
{
using Bytes = std::vector<uint8_t>;

// ── Wire-schema constants (mirrors azihsm_ddi_tbor_types) ────────────────────
constexpr size_t kMachSeedLen = 32;   // MACH_SEED_LEN
constexpr size_t kThumbprintLen = 48; // POTA/SATA_THUMBPRINT_LEN
constexpr size_t kPolicyLen = 484;    // PART_POLICY_LEN
constexpr size_t kPskLen = 32;        // PSK_LEN
constexpr size_t kRawPubLen = 96;     // raw P-384 X‖Y
constexpr size_t kSec1PubLen = 97;    // 0x04‖X‖Y

// A fixed non-default CO PSK used to clear the default-PSK gate. Any value
// works; it only has to be consistent between the rotate and the reopen.
constexpr std::array<uint8_t, kPskLen> kRotatedCoPsk = { {
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
} };

// ── Minimal portable DER encoder ─────────────────────────────────────────────
// The PTA chain is standard RFC 5280 DER (the firmware validator is a general
// parser), so the encoding is platform-independent; only the crypto
// primitives (keygen / ECDSA sign / SHA-1) are platform-specific.

void append(Bytes &dst, const Bytes &src)
{
    dst.insert(dst.end(), src.begin(), src.end());
}

Bytes concat(std::initializer_list<Bytes> parts)
{
    Bytes out;
    for (const auto &p : parts)
    {
        append(out, p);
    }
    return out;
}

/// DER definite-length octets for a content length.
Bytes der_len(size_t n)
{
    Bytes out;
    if (n < 0x80)
    {
        out.push_back(static_cast<uint8_t>(n));
        return out;
    }
    Bytes tmp;
    for (size_t v = n; v > 0; v >>= 8)
    {
        tmp.push_back(static_cast<uint8_t>(v & 0xFF));
    }
    out.push_back(static_cast<uint8_t>(0x80 | tmp.size()));
    out.insert(out.end(), tmp.rbegin(), tmp.rend());
    return out;
}

/// A DER TLV: tag ‖ length ‖ content.
Bytes tlv(uint8_t tag, const Bytes &content)
{
    Bytes out;
    out.push_back(tag);
    append(out, der_len(content.size()));
    append(out, content);
    return out;
}

/// A DER INTEGER from a big-endian magnitude (strips leading zeros, adds a
/// 0x00 pad when the high bit is set so the value stays positive).
Bytes der_int(const uint8_t *be, size_t n)
{
    size_t i = 0;
    while (i + 1 < n && be[i] == 0)
    {
        ++i;
    }
    Bytes v(be + i, be + n);
    if ((v[0] & 0x80) != 0)
    {
        v.insert(v.begin(), 0x00);
    }
    return tlv(0x02, v);
}

Bytes der_small_int(uint32_t value)
{
    const uint8_t be[4] = {
        static_cast<uint8_t>(value >> 24),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value),
    };
    return der_int(be, sizeof(be));
}

// Encoded OID contents (without the 0x06 tag/length).
const Bytes kOidEcPublicKey = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const Bytes kOidSecp384r1 = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
const Bytes kOidEcdsaSha384 = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
const Bytes kOidCn = { 0x55, 0x04, 0x03 };
const Bytes kOidSn = { 0x55, 0x04, 0x05 }; // serialNumber
const Bytes kOidBasicConstraints = { 0x55, 0x1D, 0x13 };
const Bytes kOidKeyUsage = { 0x55, 0x1D, 0x0F };
const Bytes kOidSki = { 0x55, 0x1D, 0x0E };
const Bytes kOidAki = { 0x55, 0x1D, 0x23 };

Bytes der_oid(const Bytes &content)
{
    return tlv(0x06, content);
}

/// One `RelativeDistinguishedName` with a single `type = value` attribute
/// (value encoded as a PrintableString).
Bytes der_rdn(const Bytes &type_oid, const char *value)
{
    Bytes value_bytes(value, value + std::strlen(value));
    Bytes atv = tlv(0x30, concat({ der_oid(type_oid), tlv(0x13, value_bytes) }));
    return tlv(0x31, atv);
}

/// A `Name` with a CN + serialNumber, matching the Rust x509 fixture.
Bytes der_name(const char *cn, const char *sn)
{
    return tlv(0x30, concat({ der_rdn(kOidCn, cn), der_rdn(kOidSn, sn) }));
}

Bytes der_gtime(const char *ts)
{
    Bytes bytes(ts, ts + std::strlen(ts));
    return tlv(0x18 /* GeneralizedTime */, bytes);
}

/// SubjectPublicKeyInfo for a P-384 SEC1 point.
Bytes der_spki(const uint8_t sec1[kSec1PubLen])
{
    Bytes alg = tlv(0x30, concat({ der_oid(kOidEcPublicKey), der_oid(kOidSecp384r1) }));
    Bytes point(sec1, sec1 + kSec1PubLen);
    Bytes bit_string = tlv(0x03, concat({ Bytes{ 0x00 }, point }));
    return tlv(0x30, concat({ alg, bit_string }));
}

/// One X.509v3 extension: `SEQUENCE { OID, [critical BOOLEAN], OCTETSTRING }`.
Bytes der_ext(const Bytes &oid, bool critical, const Bytes &value)
{
    Bytes body = der_oid(oid);
    if (critical)
    {
        append(body, tlv(0x01, Bytes{ 0xFF }));
    }
    append(body, tlv(0x04, value));
    return tlv(0x30, body);
}

/// The `[3] EXPLICIT` extensions block for a CA certificate: BasicConstraints
/// (cA=TRUE), KeyUsage (keyCertSign|cRLSign), SubjectKeyIdentifier, and (for a
/// non-self-signed cert) an AuthorityKeyIdentifier referencing the issuer SKI.
Bytes der_ca_extensions(const uint8_t ski[20], const uint8_t *aki)
{
    Bytes list;
    // BasicConstraints: SEQUENCE { cA BOOLEAN TRUE }.
    append(list, der_ext(kOidBasicConstraints, true, tlv(0x30, tlv(0x01, Bytes{ 0xFF }))));
    // KeyUsage: BIT STRING with keyCertSign (bit 5) + cRLSign (bit 6) → 0x06,
    // one unused trailing bit.
    append(list, der_ext(kOidKeyUsage, true, tlv(0x03, Bytes{ 0x01, 0x06 })));
    // SubjectKeyIdentifier: OCTET STRING of the 20-byte key id.
    append(list, der_ext(kOidSki, false, tlv(0x04, Bytes(ski, ski + 20))));
    if (aki != nullptr)
    {
        // AuthorityKeyIdentifier: SEQUENCE { [0] keyIdentifier }.
        Bytes akid = tlv(0x30, tlv(0x80, Bytes(aki, aki + 20)));
        append(list, der_ext(kOidAki, false, akid));
    }
    return tlv(0xA3, tlv(0x30, list));
}

// ── Platform crypto backend (keygen / ECDSA sign / SHA-1) ────────────────────
// The only platform-specific code: OpenSSL on Linux, BCrypt on Windows.

#ifdef _WIN32

/// SHA-1 of `data` (RFC 5280 key-identifier method 1).
std::array<uint8_t, 20> sha1(const uint8_t *data, size_t len)
{
    std::array<uint8_t, 20> out{};
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0)
    {
        ADD_FAILURE() << "BCryptOpenAlgorithmProvider(SHA1) failed";
        return out;
    }
    NTSTATUS status = BCryptHash(
        alg,
        nullptr,
        0,
        const_cast<PUCHAR>(data),
        static_cast<ULONG>(len),
        out.data(),
        static_cast<ULONG>(out.size())
    );
    BCryptCloseAlgorithmProvider(alg, 0);
    if (status != 0)
    {
        ADD_FAILURE() << "BCryptHash(SHA1) failed: " << status;
    }
    return out;
}

/// A synthetic P-384 CA key backed by BCrypt.
class CaKey
{
  public:
    static std::unique_ptr<CaKey> generate()
    {
        auto key = std::unique_ptr<CaKey>(new CaKey());
        if (BCryptOpenAlgorithmProvider(&key->alg_, BCRYPT_ECDSA_P384_ALGORITHM, nullptr, 0) != 0)
        {
            return nullptr;
        }
        if (BCryptGenerateKeyPair(key->alg_, &key->key_, 384, 0) != 0 ||
            BCryptFinalizeKeyPair(key->key_, 0) != 0)
        {
            return nullptr;
        }
        return key->export_sec1() ? std::move(key) : nullptr;
    }

    const std::array<uint8_t, kSec1PubLen> &sec1() const
    {
        return sec1_;
    }

    /// ECDSA-P384 / SHA-384 signature over `tbs`, DER-encoded as
    /// `SEQUENCE { INTEGER r, INTEGER s }`.
    Bytes sign(const Bytes &tbs) const
    {
        uint8_t hash[48] = {};
        BCRYPT_ALG_HANDLE hash_alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&hash_alg, BCRYPT_SHA384_ALGORITHM, nullptr, 0) != 0)
        {
            return {};
        }
        NTSTATUS hs = BCryptHash(
            hash_alg,
            nullptr,
            0,
            const_cast<PUCHAR>(tbs.data()),
            static_cast<ULONG>(tbs.size()),
            hash,
            sizeof(hash)
        );
        BCryptCloseAlgorithmProvider(hash_alg, 0);
        if (hs != 0)
        {
            return {};
        }
        ULONG sig_len = 0;
        if (BCryptSignHash(key_, nullptr, hash, sizeof(hash), nullptr, 0, &sig_len, 0) != 0)
        {
            return {};
        }
        std::vector<uint8_t> raw(sig_len);
        if (BCryptSignHash(key_, nullptr, hash, sizeof(hash), raw.data(), sig_len, &sig_len, 0) !=
            0)
        {
            return {};
        }
        raw.resize(sig_len);
        // A P-384 ECDSA signature is raw r‖s, 48 bytes each.
        if (raw.size() < 96)
        {
            ADD_FAILURE() << "BCryptSignHash returned " << raw.size() << " bytes, expected 96";
            return {};
        }
        // Raw r‖s (48 bytes each) → DER SEQUENCE { INTEGER r, INTEGER s }.
        Bytes r = der_int(raw.data(), 48);
        Bytes s = der_int(raw.data() + 48, 48);
        return tlv(0x30, concat({ r, s }));
    }

    ~CaKey()
    {
        if (key_ != nullptr)
        {
            BCryptDestroyKey(key_);
        }
        if (alg_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(alg_, 0);
        }
    }

  private:
    CaKey() = default;

    bool export_sec1()
    {
        ULONG size = 0;
        if (BCryptExportKey(key_, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &size, 0) != 0)
        {
            return false;
        }
        std::vector<uint8_t> blob(size);
        if (BCryptExportKey(key_, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob.data(), size, &size, 0) != 0)
        {
            return false;
        }
        // BCRYPT_ECCKEY_BLOB header (magic + cbKey), then X‖Y (48 bytes each).
        const size_t header = sizeof(BCRYPT_ECCKEY_BLOB);
        if (size < header + kRawPubLen)
        {
            return false;
        }
        sec1_[0] = 0x04;
        std::memcpy(sec1_.data() + 1, blob.data() + header, kRawPubLen);
        return true;
    }

    BCRYPT_ALG_HANDLE alg_ = nullptr;
    BCRYPT_KEY_HANDLE key_ = nullptr;
    std::array<uint8_t, kSec1PubLen> sec1_{};
};

#else // OpenSSL

std::array<uint8_t, 20> sha1(const uint8_t *data, size_t len)
{
    std::array<uint8_t, 20> out{};
    unsigned int out_len = 0;
    if (EVP_Digest(data, len, out.data(), &out_len, EVP_sha1(), nullptr) != 1 ||
        out_len != out.size())
    {
        ADD_FAILURE() << "EVP_Digest(SHA1) failed";
    }
    return out;
}

/// A synthetic P-384 CA key backed by OpenSSL.
class CaKey
{
  public:
    static std::unique_ptr<CaKey> generate()
    {
        auto key = std::unique_ptr<CaKey>(new CaKey());
        std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX *)> ctx(
            EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr),
            EVP_PKEY_CTX_free
        );
        if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_secp384r1) <= 0 ||
            EVP_PKEY_keygen(ctx.get(), &key->pkey_) <= 0)
        {
            return nullptr;
        }
        return key->export_sec1() ? std::move(key) : nullptr;
    }

    const std::array<uint8_t, kSec1PubLen> &sec1() const
    {
        return sec1_;
    }

    /// ECDSA-P384 / SHA-384 signature over `tbs`; OpenSSL already emits the
    /// DER `SEQUENCE { INTEGER r, INTEGER s }` form.
    Bytes sign(const Bytes &tbs) const
    {
        std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX *)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!md || EVP_DigestSignInit(md.get(), nullptr, EVP_sha384(), nullptr, pkey_) <= 0)
        {
            return {};
        }
        size_t sig_len = 0;
        if (EVP_DigestSign(md.get(), nullptr, &sig_len, tbs.data(), tbs.size()) <= 0)
        {
            return {};
        }
        Bytes sig(sig_len);
        if (EVP_DigestSign(md.get(), sig.data(), &sig_len, tbs.data(), tbs.size()) <= 0)
        {
            return {};
        }
        sig.resize(sig_len);
        return sig;
    }

    ~CaKey()
    {
        if (pkey_ != nullptr)
        {
            EVP_PKEY_free(pkey_);
        }
    }

  private:
    CaKey() = default;

    bool export_sec1()
    {
        unsigned char *raw = nullptr;
        size_t len = EVP_PKEY_get1_encoded_public_key(pkey_, &raw);
        bool ok = (raw != nullptr && len == kSec1PubLen && raw[0] == 0x04);
        if (ok)
        {
            std::memcpy(sec1_.data(), raw, kSec1PubLen);
        }
        if (raw != nullptr)
        {
            OPENSSL_free(raw);
        }
        return ok;
    }

    EVP_PKEY *pkey_ = nullptr;
    std::array<uint8_t, kSec1PubLen> sec1_{};
};

#endif // _WIN32

// ── Portable X.509 assembly + CSR parsing ────────────────────────────────────
// Structure and identity mirror the Rust
// `ddi/tbor/types/tests/harness/x509_fixture.rs` (which itself hand-assembles
// DER via `azihsm_crypto::x509_builder`); only the crypto primitives differ.

constexpr const char *kNotBefore = "20250101000000Z";
constexpr const char *kNotAfter = "20350101000000Z";
constexpr const char *kRootCn = "AZIHSM POTA Root CA";
constexpr const char *kRootSn = "POTAROOT1";
constexpr const char *kPtaCn = "AZIHSM PTA Intermediate CA";
constexpr const char *kPtaSn = "PTAINT001";

/// A 20-byte positive DER serial number seeded from `tag`.
Bytes serial(uint8_t tag)
{
    uint8_t bytes[20];
    bytes[0] = tag & 0x7F; // positive INTEGER (high bit clear)
    for (size_t i = 1; i < sizeof(bytes); ++i)
    {
        bytes[i] = static_cast<uint8_t>(tag + i);
    }
    return der_int(bytes, sizeof(bytes));
}

/// SHA-1 of a SEC1 public key — the Subject / Authority Key Identifier.
std::array<uint8_t, 20> sha1_ski(const uint8_t sec1[kSec1PubLen])
{
    return sha1(sec1, kSec1PubLen);
}

/// Assemble a signed CA certificate (`cA=TRUE`, `keyCertSign`) from its parts.
/// `aki` is the issuer's SKI for a non-self-signed cert, or null for a root.
Bytes build_ca_cert(
    const CaKey &ca,
    const uint8_t subject_sec1[kSec1PubLen],
    const char *subject_cn,
    const char *subject_sn,
    const char *issuer_cn,
    const char *issuer_sn,
    const uint8_t *aki,
    uint8_t serial_tag
)
{
    std::array<uint8_t, 20> ski = sha1_ski(subject_sec1);

    Bytes sig_alg = tlv(0x30, der_oid(kOidEcdsaSha384));
    Bytes tbs =
        tlv(0x30,
            concat({
                tlv(0xA0, der_small_int(2)), // version v3
                serial(serial_tag),
                sig_alg,
                der_name(issuer_cn, issuer_sn),
                tlv(0x30, concat({ der_gtime(kNotBefore), der_gtime(kNotAfter) })),
                der_name(subject_cn, subject_sn),
                der_spki(subject_sec1),
                der_ca_extensions(ski.data(), aki),
            }));

    Bytes sig = ca.sign(tbs);
    if (sig.empty())
    {
        return {};
    }
    Bytes sig_value = tlv(0x03, concat({ Bytes{ 0x00 }, sig }));
    return tlv(0x30, concat({ tbs, sig_alg, sig_value }));
}

/// Build a self-signed POTA Root CA certificate (DER).
Bytes build_root(const CaKey &ca)
{
    return build_ca_cert(ca, ca.sec1().data(), kRootCn, kRootSn, kRootCn, kRootSn, nullptr, 1);
}

/// Build the PTA intermediate CA certificate carrying the partition PTA key
/// (`pta_sec1`), signed by `issuer` (the POTA CA), with an AKID referencing the
/// issuer's SKID.
Bytes build_pta_intermediate(const uint8_t pta_sec1[kSec1PubLen], const CaKey &issuer)
{
    std::array<uint8_t, 20> aki = sha1_ski(issuer.sec1().data());
    return build_ca_cert(issuer, pta_sec1, kPtaCn, kPtaSn, kRootCn, kRootSn, aki.data(), 2);
}

/// A generated PTA chain (root -> PTA), DER-encoded, root-first for `PartFinal`.
struct PtaChain
{
    Bytes root_der;
    Bytes pta_der;
};

/// Build a POTA-anchored root -> PTA chain from the partition PTA key.
PtaChain make_pta_chain(const CaKey &pota_ca, const uint8_t pta_sec1[kSec1PubLen])
{
    return PtaChain{ build_root(pota_ca), build_pta_intermediate(pta_sec1, pota_ca) };
}

/// Read one DER TLV: on success advances `pos` past it and yields the tag +
/// content span.
bool der_read(
    const uint8_t *&pos,
    const uint8_t *end,
    uint8_t &tag,
    const uint8_t *&content,
    size_t &content_len
)
{
    if (pos + 2 > end)
    {
        return false;
    }
    tag = *pos++;
    size_t len = *pos++;
    if ((len & 0x80) != 0)
    {
        size_t n = len & 0x7F;
        if (pos + n > end)
        {
            return false;
        }
        len = 0;
        for (size_t i = 0; i < n; ++i)
        {
            len = (len << 8) | *pos++;
        }
    }
    if (pos + len > end)
    {
        return false;
    }
    content = pos;
    content_len = len;
    pos += len;
    return true;
}

/// Extract the SEC1 uncompressed public key (`0x04‖X‖Y`) from a DER PKCS#10
/// CSR by walking the structure to `certificationRequestInfo.subjectPKInfo`.
bool pta_pub_from_csr(const uint8_t *csr, size_t len, uint8_t out[kSec1PubLen])
{
    const uint8_t *pos = csr;
    const uint8_t *end = csr + len;
    uint8_t tag = 0;
    const uint8_t *body = nullptr;
    size_t body_len = 0;

    if (!der_read(pos, end, tag, body, body_len))
    {
        return false; // CertificationRequest SEQUENCE
    }
    const uint8_t *cri = body;
    const uint8_t *cri_end = body + body_len;
    if (!der_read(cri, cri_end, tag, body, body_len))
    {
        return false; // certificationRequestInfo SEQUENCE
    }
    const uint8_t *fields = body;
    const uint8_t *fields_end = body + body_len;
    if (!der_read(fields, fields_end, tag, body, body_len)     // version
        || !der_read(fields, fields_end, tag, body, body_len)) // subject
    {
        return false;
    }
    if (!der_read(fields, fields_end, tag, body, body_len))
    {
        return false; // subjectPKInfo SEQUENCE
    }
    const uint8_t *spki = body;
    const uint8_t *spki_end = body + body_len;
    if (!der_read(spki, spki_end, tag, body, body_len)) // algorithm
    {
        return false;
    }
    if (!der_read(spki, spki_end, tag, body, body_len) || tag != 0x03 || body_len < 1)
    {
        return false; // subjectPublicKey BIT STRING
    }
    // Skip the leading unused-bits octet; the rest is the SEC1 point.
    const uint8_t *point = body + 1;
    size_t point_len = body_len - 1;
    if (point_len != kSec1PubLen || point[0] != 0x04)
    {
        return false;
    }
    std::memcpy(out, point, kSec1PubLen);
    return true;
}

// ── Policy image ─────────────────────────────────────────────────────────────

/// Write an `Ecc384` policy key slot (`kind(2) ‖ len(2) ‖ data(96)`, LE) at
/// `off`.
void write_key_slot(std::vector<uint8_t> &policy, size_t off, const uint8_t data[kRawPubLen])
{
    policy[off] = 0; // kind = Ecc384 = 0 (LE u16)
    policy[off + 1] = 0;
    policy[off + 2] = static_cast<uint8_t>(kRawPubLen); // len = 96 (LE u16)
    policy[off + 3] = 0;
    std::memcpy(&policy[off + 4], data, kRawPubLen);
}

/// Build a 484-byte unified `PartPolicy` image binding the real POTA public
/// key, mirroring the Rust `part_policy_with_pota` fixture so `PartFinal` can
/// validate a chain anchored to it.
std::vector<uint8_t> build_part_policy(const uint8_t pota_raw[kRawPubLen])
{
    constexpr size_t kOffPota = 2;
    constexpr size_t kOffSata = 102;
    constexpr size_t kOffFlags = 418;
    constexpr size_t kOffInfo = 419;

    std::vector<uint8_t> policy(kPolicyLen, 0);
    policy[0] = 1; // version major
    policy[1] = 0; // version minor

    write_key_slot(policy, kOffPota, pota_raw);

    // SATA slot: a filler Ecc384 key (not chain-validated in this flow).
    uint8_t sata_fill[kRawPubLen];
    for (size_t i = 0; i < kRawPubLen; ++i)
    {
        sata_fill[i] = static_cast<uint8_t>((0x20 + i) | 0x80);
    }
    write_key_slot(policy, kOffSata, sata_fill);

    policy[kOffFlags] = 0;
    for (size_t i = 0; i < 64; ++i)
    {
        policy[kOffInfo + i] = 0xAB;
    }
    return policy;
}

// ── Session helpers ──────────────────────────────────────────────────────────

azihsm_handle open_co_session(azihsm_handle part_handle, const azihsm_buffer *psk_buf)
{
    azihsm_handle sess = 0;
    azihsm_session_psk psk{ 0 /* CO */, psk_buf };
    auto err = azihsm_sess_ex_open(part_handle, &psk, AZIHSM_SESSION_EX_TYPE_AUTHENTICATED, &sess);
    if (err != AZIHSM_STATUS_SUCCESS || sess == 0)
    {
        ADD_FAILURE() << "azihsm_sess_ex_open failed: " << err;
        return 0;
    }
    return sess;
}
} // namespace

azihsm_handle provision_sd_co_session(azihsm_handle part_handle)
{
    // 1. Bootstrap a CO session under the default PSK and rotate it.
    azihsm_handle bootstrap = open_co_session(part_handle, nullptr);
    if (bootstrap == 0)
    {
        return 0;
    }
    azihsm_buffer psk_buf{ const_cast<uint8_t *>(kRotatedCoPsk.data()),
                           static_cast<uint32_t>(kRotatedCoPsk.size()) };
    auto rotate_err = azihsm_sess_ex_psk_change(bootstrap, &psk_buf);
    azihsm_sess_close(bootstrap);
    if (rotate_err != AZIHSM_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "azihsm_sess_ex_psk_change failed: " << rotate_err;
        return 0;
    }

    // 2. Reopen the CO session under the rotated PSK for provisioning.
    azihsm_handle session = open_co_session(part_handle, &psk_buf);
    if (session == 0)
    {
        return 0;
    }
    auto fail = [&session](const char *msg, azihsm_status err) -> azihsm_handle {
        ADD_FAILURE() << msg << ": " << err;
        azihsm_sess_close(session);
        return 0;
    };

    // 3. Mint the POTA CA and bind its public key into the policy.
    std::unique_ptr<CaKey> pota_ca = CaKey::generate();
    if (!pota_ca)
    {
        return fail("POTA CA key generation failed", AZIHSM_STATUS_INTERNAL_ERROR);
    }
    uint8_t pota_raw[kRawPubLen];
    std::memcpy(pota_raw, pota_ca->sec1().data() + 1, kRawPubLen);
    std::vector<uint8_t> policy = build_part_policy(pota_raw);

    // Deterministic provisioning fixtures (thumbprints are stored, not
    // chain-validated in this flow).
    std::array<uint8_t, kMachSeedLen> mach_seed{};
    for (size_t i = 0; i < mach_seed.size(); ++i)
    {
        mach_seed[i] = static_cast<uint8_t>(0x40 + i);
    }
    std::array<uint8_t, kThumbprintLen> pota_tp{};
    std::array<uint8_t, kThumbprintLen> sata_tp{};
    for (size_t i = 0; i < kThumbprintLen; ++i)
    {
        pota_tp[i] = static_cast<uint8_t>(0x80 ^ i);
        sata_tp[i] = static_cast<uint8_t>(0x40 ^ i);
    }

    azihsm_buffer mach_buf{ mach_seed.data(), static_cast<uint32_t>(mach_seed.size()) };
    azihsm_buffer policy_buf{ policy.data(), static_cast<uint32_t>(policy.size()) };
    azihsm_buffer pota_buf{ pota_tp.data(), static_cast<uint32_t>(pota_tp.size()) };
    azihsm_buffer sata_buf{ sata_tp.data(), static_cast<uint32_t>(sata_tp.size()) };
    azihsm_sess_ex_part_init_params init_params{};
    init_params.mach_seed = &mach_buf;
    init_params.part_policy = &policy_buf;
    init_params.pota_thumbprint = &pota_buf;
    init_params.sata_thumbprint = &sata_buf;
    init_params.sapota_thumbprint = nullptr;

    // 4. PartInit: probe for the CSR/report sizes, then retrieve them.
    azihsm_buffer csr{ nullptr, 0 };
    azihsm_buffer report{ nullptr, 0 };
    auto probe = azihsm_sess_ex_part_init(session, &init_params, &csr, &report);
    if (probe != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        return fail("PartInit size probe unexpected status", probe);
    }
    std::vector<uint8_t> csr_bytes(csr.len);
    std::vector<uint8_t> report_bytes(report.len);
    csr = { csr_bytes.data(), static_cast<uint32_t>(csr_bytes.size()) };
    report = { report_bytes.data(), static_cast<uint32_t>(report_bytes.size()) };
    auto init_err = azihsm_sess_ex_part_init(session, &init_params, &csr, &report);
    if (init_err != AZIHSM_STATUS_SUCCESS)
    {
        return fail("PartInit failed", init_err);
    }
    csr_bytes.resize(csr.len); // shrink to the bytes actually written

    // 5. Build the POTA-anchored root -> PTA chain from the CSR public key.
    uint8_t pta_sec1[kSec1PubLen];
    if (!pta_pub_from_csr(csr_bytes.data(), csr_bytes.size(), pta_sec1))
    {
        return fail("failed to parse PTA public key from CSR", AZIHSM_STATUS_INTERNAL_ERROR);
    }
    PtaChain chain = make_pta_chain(*pota_ca, pta_sec1);
    if (chain.root_der.empty() || chain.pta_der.empty())
    {
        return fail("failed to build PTA certificate chain", AZIHSM_STATUS_INTERNAL_ERROR);
    }

    // 6. PartFinal: re-supply the policy + chain (root -> PTA) out of band.
    azihsm_buffer chain_bufs[2] = {
        { chain.root_der.data(), static_cast<uint32_t>(chain.root_der.size()) },
        { chain.pta_der.data(), static_cast<uint32_t>(chain.pta_der.size()) },
    };
    azihsm_sess_ex_part_final_params final_params{};
    final_params.part_policy = &policy_buf;
    final_params.pta_cert_chain = chain_bufs;
    final_params.pta_cert_chain_len = 2;
    final_params.prev_local_mk_backup = nullptr;

    azihsm_buffer mk_backup{ nullptr, 0 };
    auto fin_probe = azihsm_sess_ex_part_final(session, &final_params, &mk_backup);
    if (fin_probe != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        return fail("PartFinal size probe unexpected status", fin_probe);
    }
    std::vector<uint8_t> mk_bytes(mk_backup.len);
    mk_backup = { mk_bytes.data(), static_cast<uint32_t>(mk_bytes.size()) };
    auto final_err = azihsm_sess_ex_part_final(session, &final_params, &mk_backup);
    if (final_err != AZIHSM_STATUS_SUCCESS)
    {
        return fail("PartFinal failed", final_err);
    }

    return session;
}

#endif // defined(AZIHSM_FEATURE_EMU)
