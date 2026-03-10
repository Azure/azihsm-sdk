// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestRsa.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmTestHash.hpp"
#include "AziHsmTestFlags.hpp"
#include "../../../api-interface/azihsm_engine.h"
#include <functional>
#include <utility>
#include <catch2/catch_test_macros.hpp>

static void do_sign_verify_digest(
    AziHsmEngine &azihsm_engine,
    int nid,
    std::function<std::vector<unsigned char>()> &&digest_fn,
    AziHsmRsaDefaultKey key,
    unsigned int flags,
    unsigned int iterations)
{
    AziHsmRsa rsa = unwrap_test_rsa_key(azihsm_engine, key, AZIHSM_KEY_USAGE_SIGN_VERIFY);

    for (unsigned int i = 0; i < iterations; i++)
    {
        std::vector<unsigned char> digest = digest_fn();

        std::vector<unsigned char> signature;
        REQUIRE(rsa.sign(nid, signature, digest) == (IS_SIGN_FAIL(flags) ? 0 : 1));
        if (IS_SIGN_FAIL(flags))
        {
            continue;
        }

        int verify_result = 1;
        if (IS_TAMPERED_DGST(flags))
        {
            // Flip one bit
            digest[0] ^= 0x1;
            verify_result = 0;
        }

        if (IS_INVALID_DGST_LEN(flags))
        {
            // Generate random bit
            unsigned char lengthen;
            REQUIRE(RAND_bytes(&lengthen, 1) != 0);
            lengthen &= 0x1;

            size_t size = digest.size();
            digest.resize(lengthen ? ++size : --size);
            verify_result = 0;
        }

        if (IS_TAMPERED_SIG(flags))
        {
            // Flip one bit
            signature[0] ^= 0x1;
            verify_result = 0;
        }

        if (IS_INVALID_SIG_LEN(flags))
        {
            // Generate random bit
            unsigned char lengthen;
            REQUIRE(RAND_bytes(&lengthen, 1) != 0);
            lengthen &= 0x1;

            size_t size = signature.size();
            digest.resize(lengthen ? ++size : --size);
            verify_result = 0;
        }

        REQUIRE(rsa.verify(nid, signature, digest) == verify_result);
    }
}

static void do_sign_verify_random_hash_nid(
    AziHsmEngine &azihsm_engine,
    AziHsmShaHashType hash_type,
    int nid,
    AziHsmRsaDefaultKey key,
    unsigned int flags,
    unsigned int iterations)
{
    AziHsmShaHash sha_hash(hash_type);
    size_t size = sha_hash.getSize();
    std::function<std::vector<unsigned char>()>
        fn = [size]
    {
        return generate_random_vector(size);
    };
    do_sign_verify_digest(azihsm_engine, nid, std::move(fn), key, flags, iterations);
}

static void do_sign_verify_hashed_hash_nid(
    AziHsmEngine &azihsm_engine,
    AziHsmShaHashType hash_type,
    int nid,
    size_t size,
    AziHsmRsaDefaultKey key,
    unsigned int flags,
    unsigned int iterations)
{
    std::function<std::vector<unsigned char>()> fn = [hash_type, size]
    {
        return generate_hash(hash_type, size);
    };
    do_sign_verify_digest(azihsm_engine, nid, std::move(fn), key, flags, iterations);
}

static void do_sign_verify_random(
    AziHsmEngine &azihsm_engine,
    AziHsmShaHashType hash_type,
    AziHsmRsaDefaultKey key,
    unsigned int flags,
    unsigned int iterations)
{
    AziHsmShaHash sha_hash(hash_type);
    int nid = sha_hash.getNid();
    do_sign_verify_random_hash_nid(azihsm_engine, hash_type, nid, key, flags, iterations);
}

static void do_sign_verify_hashed(
    AziHsmEngine &azihsm_engine,
    AziHsmShaHashType hash_type,
    size_t size,
    AziHsmRsaDefaultKey key,
    unsigned int flags,
    unsigned int iterations)
{
    AziHsmShaHash sha_hash(hash_type);
    int nid = sha_hash.getNid();
    do_sign_verify_hashed_hash_nid(azihsm_engine, hash_type, nid, size, key, flags, iterations);
}

TEST_CASE("AZIHSM RSA sign/verify", "[AziHsmRsaSignVerify]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    // Simulated tests

    SECTION("Sign/verify with a wrapped key (SHA256 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign/verify with a wrapped key (SHA384 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign/verify with a wrapped key (SHA512 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    // Tampered tests

    SECTION("Sign/verify with a wrapped key, tampered digest (SHA256 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered digest (SHA384 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered digest (SHA512 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature (SHA256 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature (SHA384 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature (SHA512 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature and digest (SHA256 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature and digest (SHA384 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature and digest (SHA512 simulated)")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    // Hashed tests

    SECTION("Sign/verify with a wrapped key (SHA256)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign/verify with a wrapped key (SHA384)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign/verify with a wrapped key (SHA512)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    // Tampered tests

    SECTION("Sign/verify with a wrapped key, tampered digest (SHA256)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered digest (SHA384)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered digest (SHA512)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature (SHA256)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature (SHA384)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature (SHA512)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature and digest (SHA256)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA256, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature and digest (SHA384)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA384, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign/verify with a wrapped key, tampered signature and digest (SHA512)")
    {
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(azihsm_engine, AziHsmShaHashType::SHA512, 512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::TAMPERED_SIG | AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    // Invalid size tests

    SECTION("Sign/verify with invalid digest size")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);

        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);

        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
    }

    SECTION("Sign/verify with invalid signature size")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);

        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);

        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
    }

    SECTION("Sign/verify with invalid SHA256 size")
    {
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA384, NID_sha256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA384, NID_sha256, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA384, NID_sha256, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::SIGN_FAIL, 5);

        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA512, NID_sha256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA512, NID_sha256, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA512, NID_sha256, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::SIGN_FAIL, 5);
    }

    SECTION("Sign/verify with invalid SHA384 size")
    {
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA256, NID_sha384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA256, NID_sha384, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA256, NID_sha384, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::SIGN_FAIL, 5);

        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA512, NID_sha384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA512, NID_sha384, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA512, NID_sha384, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::SIGN_FAIL, 5);
    }

    SECTION("Sign/verify with invalid SHA512 size")
    {
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA256, NID_sha512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA256, NID_sha512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA256, NID_sha512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::SIGN_FAIL, 5);

        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA384, NID_sha512, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA384, NID_sha512, AziHsmRsaDefaultKey::RSA3072, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_random_hash_nid(azihsm_engine, AziHsmShaHashType::SHA384, NID_sha512, AziHsmRsaDefaultKey::RSA4096, AziHsmHashTestFlag::SIGN_FAIL, 5);
    }

    // Stress test

    SECTION("Sign and verify, 500 iterations")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::HASH_TEST_NORMAL, 500);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::HASH_TEST_NORMAL, 500);
    }

    SECTION("Sign and verify tampered digest, 500 iterations")
    {
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA256, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_DGST, 500);
        do_sign_verify_random(azihsm_engine, AziHsmShaHashType::SHA384, AziHsmRsaDefaultKey::RSA2048, AziHsmHashTestFlag::TAMPERED_DGST, 500);
    }
}
