
// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmEc.hpp"
#include "AziHsmPKeyEc.hpp"
#include "AziHsmCiphers.hpp"

#define AZIHSM_CMD_ATTEST_AES static_cast<AziHsmEngineCommand>(AZIHSM_CMD_ATTEST_EVP_PKEY_ECC + 1)

// Read 32-bit little-endian integer from byte array
int from_le_bytes(const unsigned char *bytes)
{
    int value = 0;
    for (size_t i = 0; i < 4; ++i)
    {
        value |= (bytes[i] << (8 * i));
    }
    return value;
}

TEST_CASE("AZIHSM Key Attest Tests common", "[AziHsmAttestCommon]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    AziHsmEcKeyMethod azihsm_ec_key_method(e);
    AziHsmPKeyMethod azihsm_pkey_key_method(e);

    SECTION("Built-in Unwrapping Key")
    {
        std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
        RAND_bytes(report_data.data(), report_data.size());
        std::vector<unsigned char> claim;
        size_t claim_len = 0;

        REQUIRE(azihsm_engine.attestBuiltinUnwrapKey(report_data, claim) == 1);
    }

    SECTION("Built-in Unwrapping Key - Verify claim")
    {
        std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
        RAND_bytes(report_data.data(), report_data.size());
        std::vector<unsigned char> claim;

        REQUIRE(azihsm_engine.attestBuiltinUnwrapKey(report_data, claim) == 1);

        REQUIRE(claim.size() >= 16);

        unsigned char *buffer = claim.data();
        int version = from_le_bytes(buffer);
        buffer += 4;
        int len_buffer = from_le_bytes(buffer);
        buffer += 4;
        int len_report = from_le_bytes(buffer);
        buffer += 4;
        int len_cert_chain = from_le_bytes(buffer);

        // Verify length info
        REQUIRE(version == 1);
        REQUIRE((16 + len_report + len_cert_chain) == len_buffer);
    }

    SECTION("Invalid report data length")
    {
        AziHsmEcKey ec_key(e);
        REQUIRE(ec_key.keygen(NID_secp384r1, false) == 1);

        std::vector<unsigned char> report_data(16);
        RAND_bytes(report_data.data(), report_data.size());
        std::vector<unsigned char> claim;
        size_t claim_len = 0;
        REQUIRE(azihsm_attest_ecc(e, ec_key.getKey(), report_data.data(), report_data.size(), nullptr, &claim_len) == 0);
    }

    SECTION("Invalid report data nullptr")
    {
        AziHsmPKeyEcCtx ec_keygen_ctx(azihsm_engine.getEngine(), NID_secp384r1);
        EVP_PKEY *ec_key = ec_keygen_ctx.keygen(true, true);
        REQUIRE(ec_key != nullptr);

        AziHsmPKey pkey_ec(ec_key);

        std::vector<unsigned char> claim;
        size_t claim_len = 0;
        REQUIRE(azihsm_attest_evp_pkey_ecc(e, pkey_ec.getPKey(), nullptr, REPORT_DATA_SIZE, nullptr, &claim_len) == 0);
    }

    SECTION("Insufficient claim length")
    {
        AziHsmEcKey ec_key(e);
        REQUIRE(ec_key.keygen(NID_X9_62_prime256v1, false) == 1);

        std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
        RAND_bytes(report_data.data(), report_data.size());
        std::vector<unsigned char> claim;
        size_t claim_len = 0;
        REQUIRE(azihsm_attest_ecc(e, ec_key.getKey(), report_data.data(), report_data.size(), nullptr, &claim_len) == 1);
        REQUIRE(claim_len > 0);
        size_t insufficient_claim_len = 1;
        claim.resize(insufficient_claim_len);
        REQUIRE(azihsm_attest_ecc(e, ec_key.getKey(), report_data.data(), report_data.size(), claim.data(), &insufficient_claim_len) == 0);
    }

    SECTION("not matching claim length")
    {
        AziHsmEcKey ec_key(e);
        REQUIRE(ec_key.keygen(NID_X9_62_prime256v1, false) == 1);

        std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
        RAND_bytes(report_data.data(), report_data.size());
        std::vector<unsigned char> claim;
        size_t claim_len = 0;
        REQUIRE(azihsm_attest_ecc(e, ec_key.getKey(), report_data.data(), report_data.size(), nullptr, &claim_len) == 1);
        REQUIRE(claim_len > 0);
        size_t invalid_claim_len = claim_len * 2;
        claim.resize(invalid_claim_len);
        REQUIRE(azihsm_attest_ecc(e, ec_key.getKey(), report_data.data(), report_data.size(), claim.data(), &invalid_claim_len) == 1);
    }

    SECTION("invalid key :aes Key")
    {
        AziHsmAesCipherCtx aes_ctx;
        std::vector<unsigned char> iv;
        REQUIRE(RAND_bytes(iv.data(), iv.size()) == 1);

        REQUIRE(aes_ctx.init(e, NID_aes_128_cbc, 1, nullptr, iv.data()) == 1);
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        iv.resize(iv_len);
        REQUIRE(aes_ctx.keygen(1) == 1);
        const unsigned char *key = aes_ctx.getCurrentKey();

        std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
        RAND_bytes(report_data.data(), report_data.size());
        std::vector<unsigned char> claim;
        size_t claim_len = 0;

        REQUIRE(azihsm_attest_key(e, AZIHSM_CMD_ATTEST_AES, (unsigned char *)key, report_data.data(), REPORT_DATA_SIZE, claim.data(), &claim_len) == 0);
    }

    SECTION("Invalid engine")
    {
        AziHsmEcKey ec_key(e);
        REQUIRE(ec_key.keygen(NID_secp384r1, false) == 1);

        std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
        RAND_bytes(report_data.data(), report_data.size());
        std::vector<unsigned char> claim;
        size_t claim_len = 0;
        REQUIRE(azihsm_attest_ecc(nullptr, ec_key.getKey(), report_data.data(), report_data.size(), nullptr, &claim_len) == 0);
    }

    SECTION("Null Claim Buffer")
    {
        AziHsmEcKey ec_key(e);
        REQUIRE(ec_key.keygen(NID_secp384r1, false) == 1);

        std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
        RAND_bytes(report_data.data(), report_data.size());
        size_t claim_len = 0;

        REQUIRE(azihsm_attest_ecc(e, ec_key.getKey(), report_data.data(), report_data.size(), nullptr, &claim_len) == 1);
        REQUIRE(claim_len > 0); // Should populate claim length even with null buffer
    }

    SECTION("Large Report Data")
    {
        AziHsmEcKey ec_key(e);
        REQUIRE(ec_key.keygen(NID_X9_62_prime256v1, false) == 1);

        std::vector<unsigned char> large_report_data(REPORT_DATA_SIZE * 2); // Exceed expected size
        RAND_bytes(large_report_data.data(), large_report_data.size());
        std::vector<unsigned char> claim;
        size_t claim_len = 0;

        REQUIRE(azihsm_attest_ecc(e, ec_key.getKey(), large_report_data.data(), large_report_data.size(), nullptr, &claim_len) == 0); // Large data should fail
    }

    SECTION("Attest with Reused Key")
    {
        AziHsmEcKey ec_key(e);
        REQUIRE(ec_key.keygen(NID_secp384r1, false) == 1);

        std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
        RAND_bytes(report_data.data(), report_data.size());
        size_t claim_len = 0;

        REQUIRE(azihsm_attest_ecc(e, ec_key.getKey(), report_data.data(), report_data.size(), nullptr, &claim_len) == 1);

        // Reuse the same key with new data
        std::vector<unsigned char> new_report_data(REPORT_DATA_SIZE);
        RAND_bytes(new_report_data.data(), new_report_data.size());
        REQUIRE(azihsm_attest_ecc(e, ec_key.getKey(), new_report_data.data(), new_report_data.size(), nullptr, &claim_len) == 1); // Should still succeed
    }
}
