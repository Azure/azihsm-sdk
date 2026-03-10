// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmEngine.hpp"
#include "AziHsmTestHash.hpp"
#include <stdexcept>
#include <vector>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

std::vector<unsigned char> generate_random_vector(size_t size)
{
    std::vector<unsigned char> data(size);
    if (RAND_bytes(data.data(), data.size()) != 1)
    {
        throw std::runtime_error("Could not generate random vector");
    }
    return data;
}

std::vector<unsigned char> generate_hash(AziHsmShaHashType hash_type, size_t size)
{
    std::vector<unsigned char> plain_data = generate_random_vector(size);
    AziHsmShaHash sha_hash(hash_type);
    return sha_hash.hashData(plain_data);
}