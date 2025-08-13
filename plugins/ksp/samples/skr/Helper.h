//-------------------------------------------------------------------------------------------------
// <copyright file="Helper.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <vector>
#include <iostream>
#include <numeric>
#include <atomic>
#include <random>

std::vector<unsigned char> base64_to_binary(const std::string &base64_data)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::vector<unsigned char>(It(std::begin(base64_data)), It(std::end(base64_data))), [](char c)
                                                { return c == '\0'; });
}

std::string binary_to_base64(const std::vector<unsigned char> &binary_data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));
    return tmp.append((3 - binary_data.size() % 3) % 3, '=');
}

std::string binary_to_base64url(const std::vector<unsigned char> &binary_data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));

    // For encoding to base64url, replace "+" with "-" and "/" with "_"
    boost::replace_all(tmp, "+", "-");
    boost::replace_all(tmp, "/", "_");

    // We do not need to add padding characters while url encoding.
    return tmp;
}

std::vector<unsigned char> base64url_to_binary(const std::string &base64_data)
{
    std::string stringData = base64_data;

    // While decoding base64 url, replace - with + and _ with + and
    // use stanard base64 decode. we dont need to add padding characters. underlying library handles it.
    boost::replace_all(stringData, "-", "+");
    boost::replace_all(stringData, "_", "/");

    return base64_to_binary(stringData);
}

std::string base64_encode(const std::string &data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(data)), It(std::end(data)));
    return tmp.append((3 - data.size() % 3) % 3, '=');
}

/* See header */
std::string base64_decode(const std::string &data)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(data)), It(std::end(data))), [](char c)
                                                { return c == '\0'; });
}

std::string base64url_decode(const std::string &data)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

    // Replace base64url-specific characters
    std::string base64url = data;
    boost::algorithm::replace_all(base64url, "-", "+");
    boost::algorithm::replace_all(base64url, "_", "/");

    // Perform base64url decoding
    std::string decoded = std::string(It(std::begin(base64url)), It(std::end(base64url)));

    // Remove padding characters
    size_t padding = decoded.find_last_not_of('\0');
    if (padding != std::string::npos)
    {
        decoded.resize(padding + 1);
    }

    return decoded;
}

void generateRandomByteArray(int length, BYTE *byteArray)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    // Generate the byte array
    for (int i = 0; i < length; i++)
    {
        byteArray[i] = static_cast<unsigned char>(dis(gen));
    }
}