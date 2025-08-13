// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmEc.hpp"
#include "AziHsmTestEc.hpp"
#include "AziHsmTestEngine.hpp"
#include <openssl/ec.h>
#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <cstring>

void validate_ecdh(AziHsmEngine &azihsm_engine, int nid, KeyType key_type, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1, bool edch = true)
{
    AziHsmEcKey Alice(azihsm_engine.getEngine()), Bob(azihsm_engine.getEngine());
    int expected_secret_size = 256;
    EC_KEY *AliceKey, *BobKey;

    // Generate Alice's key
    if (key_type == KeyType::UNWRAP)
    {
        AliceKey = unwrap_test_ec_key(
            azihsm_engine,
            nid,
            true,
            digest_kind,
            nullptr,
            AZIHSM_AVAILABILITY_SESSION,
            0);
        REQUIRE(AliceKey != nullptr);
    }
    else
    {
        REQUIRE(Alice.keygen(nid, edch) == 1);
        AliceKey = Alice.getKey();
    }
    const EC_POINT *AlicePubKey = EC_KEY_get0_public_key(AliceKey);
    REQUIRE(AlicePubKey != nullptr);

    // Generate Bob's key
    if (key_type == KeyType::UNWRAP)
    {
        BobKey = unwrap_test_ec_key(
            azihsm_engine,
            nid,
            true,
            digest_kind,
            nullptr,
            AZIHSM_AVAILABILITY_SESSION,
            1);
        REQUIRE(BobKey != nullptr);
    }
    else
    {
        REQUIRE(Bob.keygen(nid, true) == 1);
        BobKey = Bob.getKey();
    }
    const EC_POINT *BobPubKey = EC_KEY_get0_public_key(BobKey);
    REQUIRE(BobPubKey != nullptr);

    // Perform ECDH for Alice
    int AliceSecretSize = expected_secret_size;
    std::vector<unsigned char> AliceSecret(AliceSecretSize);
    REQUIRE(ECDH_compute_key(
                AliceSecret.data(),
                AliceSecretSize,
                BobPubKey,
                AliceKey,
                nullptr) == 8);

    // Perform ECDH for Bob
    int BobSecretSize = expected_secret_size;
    std::vector<unsigned char> BobSecret(BobSecretSize);
    REQUIRE(ECDH_compute_key(
                BobSecret.data(),
                BobSecretSize,
                AlicePubKey,
                BobKey,
                nullptr) == 8);

    // Check if the secrets match
    REQUIRE(std::memcmp(AliceSecret.data(), BobSecret.data(), 8) != 0);

    if (key_type == KeyType::UNWRAP)
    {
        EC_KEY_free(AliceKey);
        EC_KEY_free(BobKey);
    }
}

void validate_ecdh_copy_key(AziHsmEngine &azihsm_engine, int nid, KeyType key_type, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1, bool edch = true)
{
    AziHsmEcKey Alice(azihsm_engine.getEngine()), Bob(azihsm_engine.getEngine());
    int expected_secret_size = 256;

    EC_KEY *AliceKey, *BobKey;

    // Generate Alice's key
    if (key_type == KeyType::UNWRAP)
    {
        AliceKey = unwrap_test_ec_key(
            azihsm_engine,
            nid,
            true,
            digest_kind,
            nullptr,
            AZIHSM_AVAILABILITY_SESSION,
            0);
        REQUIRE(AliceKey != nullptr);
    }
    else
    {
        REQUIRE(Alice.keygen(nid, edch) == 1);
        AliceKey = Alice.getKey();
    }
    const EC_POINT *AlicePubKey = EC_KEY_get0_public_key(AliceKey);
    REQUIRE(AlicePubKey != nullptr);

    // Generate Bob's key
    if (key_type == KeyType::UNWRAP)
    {
        BobKey = unwrap_test_ec_key(
            azihsm_engine,
            nid,
            true,
            digest_kind,
            nullptr,
            AZIHSM_AVAILABILITY_SESSION,
            1);
        REQUIRE(BobKey != nullptr);
    }
    else
    {
        REQUIRE(Bob.keygen(nid, true) == 1);
        BobKey = Bob.getKey();
    }
    const EC_POINT *BobPubKey = EC_KEY_get0_public_key(BobKey);
    REQUIRE(BobPubKey != nullptr);

    // Get a Copy of Bob's key
    EC_KEY *BobCopyKey = EC_KEY_new_by_curve_name(nid);
    REQUIRE(EC_KEY_copy(BobCopyKey, BobKey) != nullptr);
    REQUIRE(BobCopyKey != nullptr);
    const EC_POINT *BobCopyPubKey = EC_KEY_get0_public_key(BobCopyKey);
    REQUIRE(BobCopyPubKey != nullptr);

    REQUIRE(ec_keys_compare(BobKey, BobCopyKey) == 0);

    // Perform ECDH for Alice
    int AliceSecretSize = expected_secret_size;
    std::vector<unsigned char> AliceSecret(AliceSecretSize);
    REQUIRE(ECDH_compute_key(
                AliceSecret.data(),
                AliceSecretSize,
                BobPubKey,
                AliceKey,
                nullptr) == 8);

    // Perform ECDH for Bob
    int BobSecretSize = expected_secret_size;
    std::vector<unsigned char> BobSecret(BobSecretSize);
    REQUIRE(ECDH_compute_key(
                BobSecret.data(),
                BobSecretSize,
                AlicePubKey,
                BobKey,
                nullptr) == 8);

    // Perform ECDH for BobCopy
    int BobCopySecretSize = expected_secret_size;
    std::vector<unsigned char> BobCopySecret(BobCopySecretSize);
    REQUIRE(ECDH_compute_key(
                BobCopySecret.data(),
                BobCopySecretSize,
                AlicePubKey,
                BobCopyKey,
                nullptr) == 8);

    // Check if the secrets match
    REQUIRE(std::memcmp(AliceSecret.data(), BobSecret.data(), 8) != 0);
    REQUIRE(std::memcmp(BobSecret.data(), BobCopySecret.data(), 8) != 0);
    REQUIRE(std::memcmp(AliceSecret.data(), BobCopySecret.data(), 8) != 0);

    // Attempt to sign with the copied key and fail
    // Just use SHA1 for the digest
    std::vector<unsigned char> dgst(20);
    REQUIRE(RAND_bytes(dgst.data(), dgst.size()) == 1);
    std::vector<unsigned char> sig;
    unsigned int siglen = 0;
    REQUIRE(ECDSA_sign(0, dgst.data(), dgst.size(), sig.data(), &siglen, BobCopyKey) == 0);

    if (key_type == KeyType::UNWRAP)
    {
        EC_KEY_free(AliceKey);
        EC_KEY_free(BobKey);
    }

    EC_KEY_free(BobCopyKey);
}

TEST_CASE("AZIHSM ECDH", "[AziHsmEcdh]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("ECDH (X9_62_prime256v1)")
    {

        // keygen
        validate_ecdh(azihsm_engine, NID_X9_62_prime256v1, KeyType::KEYGEN);

        // keygen - copy key
        validate_ecdh_copy_key(azihsm_engine, NID_X9_62_prime256v1, KeyType::KEYGEN);

        // unwrap
        validate_ecdh(azihsm_engine, NID_X9_62_prime256v1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA1);
        validate_ecdh(azihsm_engine, NID_X9_62_prime256v1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA256);
        validate_ecdh(azihsm_engine, NID_X9_62_prime256v1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA384);
        validate_ecdh(azihsm_engine, NID_X9_62_prime256v1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA512);

        // unwrap - copy key
        validate_ecdh_copy_key(azihsm_engine, NID_X9_62_prime256v1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA1);
        validate_ecdh_copy_key(azihsm_engine, NID_X9_62_prime256v1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA256);
        validate_ecdh_copy_key(azihsm_engine, NID_X9_62_prime256v1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA384);
        validate_ecdh_copy_key(azihsm_engine, NID_X9_62_prime256v1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA512);
    }

    SECTION("ECDH (secp384r1)")
    {
        // keygen
        validate_ecdh(azihsm_engine, NID_secp384r1, KeyType::KEYGEN);

        // keygen - copy key
        validate_ecdh_copy_key(azihsm_engine, NID_secp384r1, KeyType::KEYGEN);

        // unwrap
        validate_ecdh(azihsm_engine, NID_secp384r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA1);
        validate_ecdh(azihsm_engine, NID_secp384r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA256);
        validate_ecdh(azihsm_engine, NID_secp384r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA384);
        validate_ecdh(azihsm_engine, NID_secp384r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA512);

        // unwrap - copy key
        validate_ecdh_copy_key(azihsm_engine, NID_secp384r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA1);
        validate_ecdh_copy_key(azihsm_engine, NID_secp384r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA256);
        validate_ecdh_copy_key(azihsm_engine, NID_secp384r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA384);
        validate_ecdh_copy_key(azihsm_engine, NID_secp384r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA512);
    }

    SECTION("ECDH (secp521r1)")
    {
        // keygen
        validate_ecdh(azihsm_engine, NID_secp521r1, KeyType::KEYGEN);

        // keygen - copy key
        validate_ecdh_copy_key(azihsm_engine, NID_secp521r1, KeyType::KEYGEN);

        // unwrap
        validate_ecdh(azihsm_engine, NID_secp521r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA1);
        validate_ecdh(azihsm_engine, NID_secp521r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA256);
        validate_ecdh(azihsm_engine, NID_secp521r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA384);
        validate_ecdh(azihsm_engine, NID_secp521r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA512);

        // unwrap - copy key
        validate_ecdh_copy_key(azihsm_engine, NID_secp521r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA1);
        validate_ecdh_copy_key(azihsm_engine, NID_secp521r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA256);
        validate_ecdh_copy_key(azihsm_engine, NID_secp521r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA384);
        validate_ecdh_copy_key(azihsm_engine, NID_secp521r1, KeyType::UNWRAP, AziHsmDigestKind::AZIHSM_DIGEST_SHA512);
    }
}
