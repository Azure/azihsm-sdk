//-------------------------------------------------------------------------------------------------
// <copyright file="ArgumentValidator.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once
#include <iostream>
#include <string>
#include <locale>

#define IMPORT_KEY_NAME L"ImportKey"
#define TARGET_KEY_NAME L"TargetKey"
#define MIN_ARGS 6

enum class VaultType
{
    AKV,
    MHSM
};

enum class KeyType
{
    RSA_2048,
    RSA_3072,
    RSA_4096,
    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
    ECDH_P256,
    ECDH_P384,
    ECDH_P521,
    AES_128,
    AES_192,
    AES_256
};

class ArgumentValidator
{
public:
    static bool ValidateVaultType(const std::string &type, VaultType &vaultType)
    {
        std::string typeLowerCase = ToLowerCase(type);
        if (typeLowerCase == "akv")
        {
            vaultType = VaultType::AKV;
            return true;
        }
        else if (typeLowerCase == "mhsm")
        {
            vaultType = VaultType::MHSM;
            return true;
        }
        return false;
    }

    static bool ValidateKeyType(const std::string &type, KeyType &keyType)
    {
        std::string typeLowerCase = ToLowerCase(type);
        if (typeLowerCase == "rsa_2048")
        {
            keyType = KeyType::RSA_2048;
            return true;
        }
        else if (typeLowerCase == "rsa_3072")
        {
            keyType = KeyType::RSA_3072;
            return true;
        }
        else if (typeLowerCase == "rsa_4096")
        {
            keyType = KeyType::RSA_4096;
            return true;
        }
        else if (typeLowerCase == "ecdsa_p256")
        {
            keyType = KeyType::ECDSA_P256;
            return true;
        }
        else if (typeLowerCase == "ecdsa_p384")
        {
            keyType = KeyType::ECDSA_P384;
            return true;
        }
        else if (typeLowerCase == "ecdsa_p521")
        {
            keyType = KeyType::ECDSA_P521;
            return true;
        }
        else if (typeLowerCase == "ecdh_p256")
        {
            keyType = KeyType::ECDH_P256;
            return true;
        }
        else if (typeLowerCase == "ecdh_p384")
        {
            keyType = KeyType::ECDH_P384;
            return true;
        }
        else if (typeLowerCase == "ecdh_p521")
        {
            keyType = KeyType::ECDH_P521;
            return true;
        }
        else if (typeLowerCase == "aes_128")
        {
            keyType = KeyType::AES_128;
            return true;
        }
        else if (typeLowerCase == "aes_192")
        {
            keyType = KeyType::AES_192;
            return true;
        }
        else if (typeLowerCase == "aes_256")
        {
            keyType = KeyType::AES_256;
            return true;
        }
        return false;
    }

private:
    static std::string ToLowerCase(const std::string &str)
    {
        std::string result;
        std::locale loc;
        for (char ch : str)
        {
            result += std::tolower(ch, loc);
        }
        return result;
    }
};