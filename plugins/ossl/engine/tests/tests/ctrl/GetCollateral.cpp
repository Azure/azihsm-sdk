// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include <catch2/catch_test_macros.hpp>

// Helper functions (can be made global if needed)
static X509 *cert_from_pem(const std::vector<unsigned char> &cert_pem)
{
    BIO *bio = BIO_new_mem_buf(cert_pem.data(), cert_pem.size());
    REQUIRE(bio != nullptr);
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    REQUIRE(cert != nullptr);
    BIO_free(bio);
    return cert;
}

static X509 *cert_from_der(const std::vector<unsigned char> &cert_der)
{
    const unsigned char *ptr = cert_der.data();
    X509 *cert = d2i_X509(nullptr, &ptr, cert_der.size());
    REQUIRE(cert != nullptr);
    return cert;
}

TEST_CASE("AZIHSM Get Collateral", "[AziHsmGetCollateral]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    std::vector<unsigned char> cert_blob = azihsm_engine.getCollateral();
    REQUIRE(cert_blob.size() > 0);
    X509 *cert = cert_from_pem(cert_blob);
    REQUIRE(cert != nullptr);

    // Get the public key from the certificate
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    REQUIRE(pkey != nullptr);

    X509_free(cert);
    EVP_PKEY_free(pkey);
}