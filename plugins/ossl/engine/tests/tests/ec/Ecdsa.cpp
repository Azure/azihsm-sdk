// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestEc.hpp"
#include "AziHsmTestHash.hpp"
#include "AziHsmTestFlags.hpp"
#include <openssl/ec.h>
#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <functional>
#include <utility>

static void do_sign_verify_data(
    ENGINE *e,
    int nid,
    std::function<std::vector<unsigned char>()> &&digest_fn,
    unsigned int flags,
    unsigned int iterations)
{
    AziHsmEcKey Eckey(e);
    REQUIRE(Eckey.keygen(nid, false) == 1);

    const size_t size = Eckey.getSize();

    for (unsigned int i = 0; i < iterations; i++)
    {
        std::vector<unsigned char> digest = digest_fn();
        std::vector<unsigned char> signature(size);

        REQUIRE(Eckey.sign(digest, signature) == (IS_SIGN_FAIL(flags) ? 0 : 1));
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
            signature.resize(lengthen ? ++size : --size);
            verify_result = 0;
        }

        if (IS_COPY_KEY(flags))
        {
            AziHsmEcKey ec_key_copy = Eckey.copy();
            REQUIRE(ec_key_copy.verify(digest, signature) == verify_result);

            // generate key2 for ecdh
            AziHsmEcKey ec_key_2(e);
            REQUIRE(ec_key_2.keygen(nid, true) == 1);
            // Try to derive and fail
            std::vector<unsigned char> secret1(256);
            REQUIRE(ECDH_compute_key(
                        secret1.data(),
                        secret1.size(),
                        ec_key_2.getPublicKey(),
                        ec_key_copy.getKey(),
                        nullptr) == 0);
        }

        REQUIRE(Eckey.verify(digest, signature) == verify_result);
    }
}

static void do_sign_verify_ecdsa_data(
    ENGINE *e,
    int nid,
    std::function<std::vector<unsigned char>()> &&digest_fn,
    unsigned int flags,
    unsigned int iterations)
{
    AziHsmEcKey Eckey(e);
    REQUIRE(Eckey.keygen(nid, false) == 1);

    for (unsigned int i = 0; i < iterations; i++)
    {
        std::vector<unsigned char> digest = digest_fn();

        ECDSA_SIG *signature = Eckey.ecdsa_sig_sign(digest);
        if (IS_SIGN_FAIL(flags))
        {
            REQUIRE(signature == nullptr);
            return;
        }
        else
        {
            REQUIRE(signature != nullptr);
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
            // Tamper with the ECDSA_SIG structure by modifying the 'r' value
            const BIGNUM *r, *s;
            ECDSA_SIG_get0(signature, &r, &s);
            BIGNUM *tampered_r = BN_dup(r);
            BN_add_word(tampered_r, 1); // Modify the value of r to simulate tampering

            ECDSA_SIG_set0(signature, tampered_r, BN_dup(s));
            verify_result = 0; // Verification should fail
        }

        if (IS_COPY_KEY(flags))
        {
            AziHsmEcKey ec_key_copy = Eckey.copy();
            REQUIRE(ec_key_copy.ecdsa_sig_verify(digest, signature) == verify_result);
        }

        REQUIRE(Eckey.ecdsa_sig_verify(digest, signature) == verify_result);

        ECDSA_SIG_free(signature);
    }
}

static void do_sign_verify_random(
    ENGINE *e,
    int nid,
    AziHsmShaHashType hash_type,
    unsigned int flags,
    unsigned int iterations)
{
    std::function<std::vector<unsigned char>()> fn = [hash_type]
    {
        AziHsmShaHash sha_hash(hash_type);
        return generate_random_vector(sha_hash.getSize());
    };
    do_sign_verify_data(e, nid, std::move(fn), flags, iterations);
}

static void do_sign_verify_ecdsa_random(
    ENGINE *e,
    int nid,
    AziHsmShaHashType hash_type,
    unsigned int flags,
    unsigned int iterations)
{
    std::function<std::vector<unsigned char>()> fn = [hash_type]
    {
        AziHsmShaHash sha_hash(hash_type);
        return generate_random_vector(sha_hash.getSize());
    };
    do_sign_verify_ecdsa_data(e, nid, std::move(fn), flags, iterations);
}

static void do_sign_verify_hashed(
    ENGINE *e,
    int nid,
    AziHsmShaHashType hash_type,
    size_t size,
    unsigned int flags,
    unsigned int iterations)
{
    std::function<std::vector<unsigned char>()> fn = [hash_type, size]
    {
        return generate_hash(hash_type, size);
    };
    do_sign_verify_data(e, nid, std::move(fn), flags, iterations);
}

static void do_sign_verify_ecdsa_hashed(
    ENGINE *e,
    int nid,
    AziHsmShaHashType hash_type,
    size_t size,
    unsigned int flags,
    unsigned int iterations)
{
    std::function<std::vector<unsigned char>()> fn = [hash_type, size]
    {
        return generate_hash(hash_type, size);
    };
    do_sign_verify_ecdsa_data(e, nid, std::move(fn), flags, iterations);
}

TEST_CASE("AZIHSM ECDSA Valid Length", "[AziHsmEcdsaValidLength]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    // Valid length tests
    // These tests use the same data size as the digest size.
    // There's no dgst calculated on the data in this case to sign.

    SECTION("Sign and verify (SHA1)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify tampered data (SHA1)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify tampered signature (SHA1)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify tampered signature and data (SHA1)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST | AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST | AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST | AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with copy key (SHA1)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify (SHA256)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify tampered data (SHA256)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify tampered signature (SHA256)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify tampered signature and data (SHA256)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_DGST | AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_DGST | AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_DGST | AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with copy key (SHA256)")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify (SHA384)")
    {
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify tampered data (SHA384)")
    {
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify tampered signature (SHA384)")
    {
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify tampered signature and data (SHA384)")
    {
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_DGST | AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_DGST | AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with copy key (SHA384)")
    {
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify (SHA512)")
    {
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify tampered data (SHA512)")
    {
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify tampered signature (SHA512)")
    {
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify tampered signature and data (SHA512)")
    {
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::TAMPERED_DGST | AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with copy key (SHA512)")
    {
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG) (SHA1)")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify tampered data (ECDSA_SIG) (SHA1)")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify tampered signature (ECDSA_SIG) (SHA1)")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with copy key (ECDSA_SIG) (SHA1)")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG) (SHA256)")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify tampered data (ECDSA_SIG) (SHA256)")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify tampered signature (ECDSA_SIG) (SHA256)")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with copy key (ECDSA_SIG) (SHA256)")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG) (SHA384)")
    {
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify tampered data (ECDSA_SIG) (SHA384)")
    {
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify tampered signature (ECDSA_SIG) (SHA384)")
    {
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify copy key (ECDSA_SIG) (SHA384)")
    {
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG) (SHA512)")
    {
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify tampered data (ECDSA_SIG) (SHA512)")
    {
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify tampered signature (ECDSA_SIG) (SHA512)")
    {
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify copy key (ECDSA_SIG) (SHA512)")
    {
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::COPY_KEY, 5);
    }
}

TEST_CASE("AZIHSM ECDSA Invalid Length", "[AziHsmEcdsaInvalidLength]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    // Invalid length tests

    SECTION("Sign and verify, invalid signature length, SHA1")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
    }

    SECTION("Sign and verify, invalid digest length, SHA1")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
    }

    SECTION("Sign and verify, invalid signature length, SHA256")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
    }

    SECTION("Sign and verify, invalid digest length, SHA256")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
    }

    SECTION("Sign and verify, unsupported length, SHA384")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::SIGN_FAIL, 5);
    }

    SECTION("Sign and verify, invalid signature length, SHA384")
    {
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
    }

    SECTION("Sign and verify, invalid digest length, SHA384")
    {
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
    }

    SECTION("Sign and verify, invalid digest length, SHA512")
    {
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
    }

    SECTION("Sign and verify, invalid signature length, SHA512")
    {
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::INVALID_SIG_LEN, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG), invalid digest length, SHA1")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG), invalid digest length, SHA256")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA256, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG), unsupported length, SHA384")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::SIGN_FAIL, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG), invalid digest length, SHA384")
    {
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA384, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG), invalid digest length, SHA512")
    {
        do_sign_verify_ecdsa_random(e, NID_secp521r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::INVALID_DGST_LEN, 5);
    }

    SECTION("Sign and verify (ECDSA_SIG), unsupported length SHA512")
    {
        do_sign_verify_ecdsa_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::SIGN_FAIL, 5);
        do_sign_verify_ecdsa_random(e, NID_secp384r1, AziHsmShaHashType::SHA512, AziHsmHashTestFlag::SIGN_FAIL, 5);
    }
}

TEST_CASE("AZIHSM ECDSA Hashed data", "[AziHsmEcdsaHashedData]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    // Hashed data tests
    // These tests use data size of 512 and hash the data before signing.

    SECTION("Sign and verify with hashed data (SHA1)")
    {
        do_sign_verify_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify with hashed data - tampered digest (SHA1)")
    {
        do_sign_verify_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify with hashed data - tampered signature (SHA1)")
    {
        do_sign_verify_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with hashed data - copy key (SHA1)")
    {
        do_sign_verify_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify with hashed data (SHA256)")
    {
        do_sign_verify_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify with hashed data - tampered digest (SHA256)")
    {
        do_sign_verify_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify with hashed data - tampered signature (SHA256)")
    {
        do_sign_verify_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with hashed data - copy key (SHA256)")
    {
        do_sign_verify_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify with hashed data (SHA384)")
    {
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA384, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA384, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify with hashed data - tampered digest (SHA384)")
    {
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA384, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA384, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify with hashed data - tampered signature (SHA384)")
    {
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA384, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA384, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with hashed data - copy key (SHA384)")
    {
        do_sign_verify_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA384, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA384, 512, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify with hashed data (SHA512)")
    {
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA512, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify with hashed data - tampered digest (SHA512)")
    {
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA512, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify with hashed data - tampered signature (SHA512)")
    {
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA512, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with hashed data - copy key (SHA512)")
    {
        do_sign_verify_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA512, 512, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify with hashed data (ECDSA_SIG) (SHA1)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify with hashed data - tampered digest (ECDSA_SIG) (SHA1)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify with hashed data - tampered signature (ECDSA_SIG) (SHA1)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with hashed data - copy key (ECDSA_SIG) (SHA1)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA1, 512, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify with hashed data (ECDSA_SIG) (SHA256)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify with hashed data - tampered digest (ECDSA_SIG) (SHA256)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify with hashed data - tampered signature (ECDSA_SIG) (SHA256)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with hashed data - copy key (ECDSA_SIG) (SHA256)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify with hashed data (ECDSA_SIG) (SHA384)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify with hashed data - tampered digest (ECDSA_SIG) (SHA384)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify with hashed data - tampered signature (ECDSA_SIG) (SHA384)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with hashed data - copy key (ECDSA_SIG) (SHA384)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_secp384r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::COPY_KEY, 5);
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA256, 512, AziHsmHashTestFlag::COPY_KEY, 5);
    }

    SECTION("Sign and verify with hashed data (ECDSA_SIG) (SHA512)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA512, 512, AziHsmHashTestFlag::HASH_TEST_NORMAL, 5);
    }

    SECTION("Sign and verify with hashed data - tampered digest (ECDSA_SIG) (SHA512)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA512, 512, AziHsmHashTestFlag::TAMPERED_DGST, 5);
    }

    SECTION("Sign and verify with hashed data - tampered signature (ECDSA_SIG) (SHA512)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA512, 512, AziHsmHashTestFlag::TAMPERED_SIG, 5);
    }

    SECTION("Sign and verify with hashed data - copy key (ECDSA_SIG) (SHA512)")
    {
        do_sign_verify_ecdsa_hashed(e, NID_secp521r1, AziHsmShaHashType::SHA512, 512, AziHsmHashTestFlag::COPY_KEY, 5);
    }
}

TEST_CASE("AZIHSM ECDSA Stress Tests", "[AziHsmEcdsaStress]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);
    // Stress tests

    SECTION("Sign and verify (SHA1 simulated), 500 iterations")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::HASH_TEST_NORMAL, 500);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::HASH_TEST_NORMAL, 500);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::HASH_TEST_NORMAL, 500);
    }

    SECTION("Sign and verify tampered data (SHA1 simulated), 500 iterations")
    {
        do_sign_verify_random(e, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST, 500);
        do_sign_verify_random(e, NID_secp384r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST, 500);
        do_sign_verify_random(e, NID_secp521r1, AziHsmShaHashType::SHA1, AziHsmHashTestFlag::TAMPERED_DGST, 500);
    }
}

TEST_CASE("AZIHSM ECDSA Invalid Keys", "[AziHsmEcdsaInvalidKeys]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    // Invalid keys
    SECTION("Sign and verify (invalid key)")
    {
        EC_KEY *key = ec_key_new_with_engine(e, NID_X9_62_prime256v1);

        std::vector<unsigned char> plain_data(20);
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        // Arbitrarily chosen
        unsigned int siglen = 20;
        std::vector<unsigned char> signature(siglen);

        REQUIRE(ECDSA_sign(
                    0,
                    plain_data.data(),
                    plain_data.size(),
                    signature.data(),
                    &siglen,
                    key) == 0);
        REQUIRE(ECDSA_verify(
                    0,
                    plain_data.data(),
                    plain_data.size(),
                    signature.data(),
                    siglen,
                    key) == -1);

        EC_KEY_free(key);
    }

    SECTION("Sign and verify (ECDSA_SIG) (invalid key)")
    {
        EC_KEY *key = ec_key_new_with_engine(e, NID_X9_62_prime256v1);

        std::vector<unsigned char> plain_data(20);
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        ECDSA_SIG *signature = ECDSA_do_sign(plain_data.data(), plain_data.size(), key);
        REQUIRE(signature == nullptr);

        REQUIRE(ECDSA_do_verify(plain_data.data(), plain_data.size(), signature, key) == -1);

        EC_KEY_free(key);
    }
}
