//-------------------------------------------------------------------------------------------------
// <copyright file="SkrManager.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once
#include "HttpClient.h"
#include <nlohmann/json.hpp>
#include <string>
#include <chrono>
#include <thread>
#include <math.h>
#include <fstream>
#include <ctime>
#include <windows.h>
#include <sstream>

using json = nlohmann::json;

/**
 * @class SkrManager
 * @brief Manages the Secure Key Release (SKR) process.
 */
class SkrManager
{
public:
    /**
     * @brief Constructor for SkrManager.
     *
     * @param msi_token The MSI token.
     * @param attestation_token The attestation token.
     * @param vault_url The URL of the vault.
     * @param key_name The name of the key.
     * @param key_enc_alg The key encryption algorithm.
     */
    SkrManager(
        const std::string &msi_token,
        const std::string &attestation_token,
        const std::string &vault_url,
        const std::string &key_name,
        const std::string &key_enc_alg) : msi_token_(msi_token), attestation_token_(attestation_token), vault_url_(vault_url), key_name_(key_name), key_enc_alg_(key_enc_alg) {}

    /**
     * @brief Performs the Secure Key Release (SKR) process.
     *
     * @return A string containing the cipher text.
     */
    std::string PerformSkr()
    {
        HttpClient httpClient;
        std::string url = CreateKeyUrl();
        httpClient.SetUrl(url);
        httpClient.SetTimeout(20L);

        struct curl_slist *headers = NULL;
        std::string content_type = "Content-Type: application/json";
        headers = curl_slist_append(headers, content_type.c_str());
        std::string authorization = std::string("Authorization: Bearer ") + msi_token_;
        headers = curl_slist_append(headers, authorization.c_str());
        httpClient.SetHeaders(headers);

        httpClient.SetHttpMethod("POST");

        std::string payload = CreateSkrPayload();
        httpClient.SetPayload(payload);

        std::string response = "";
        bool bool_result = false;
        bool_result = httpClient.PerformRequest(response);
        if (!bool_result)
        {
            printf("Failed to perform SKR");
        }

        json root = json::parse(response.c_str());
        std::string wrapped_blob = root["value"].get<std::string>();
        std::string cipher_text = ParseWrappedBlob(wrapped_blob);
        return cipher_text;
    }

private:
    std::string msi_token_;
    std::string attestation_token_;
    std::string vault_url_;
    std::string key_name_;
    std::string key_enc_alg_;

    /**
     * @brief Creates the payload for the SKR request.
     *
     * @return A JSON string containing the SKR payload.
     */
    std::string CreateSkrPayload()
    {
        json root;
        root["target"] = attestation_token_;
        root["enc"] = key_enc_alg_;
        return root.dump();
    }

    /**
     * @brief Creates the URL for the key.
     *
     * @return A string containing the key URL.
     */
    std::string CreateKeyUrl()
    {
        std::string formattedVaultUrl = vault_url_;

        if (formattedVaultUrl.back() == '/')
        {
            formattedVaultUrl.pop_back();
        }

        // Construct the key URL
        std::stringstream keyUrlStream;
        keyUrlStream << formattedVaultUrl << "/keys/" << key_name_ << "/release?api-version=7.3";

        return keyUrlStream.str();
    }

    /**
     * @brief Parses the wrapped blob to extract the cipher text.
     *
     * @param wrapped_blob The wrapped blob.
     * @return A string containing the cipher text.
     */
    std::string ParseWrappedBlob(const std::string &wrapped_blob)
    {
        std::vector<std::string> skrResponseTokens;
        boost::split(skrResponseTokens, wrapped_blob, [](char c)
                     { return c == '.'; });

        if (skrResponseTokens.size() != 3)
        {
            printf("Invalid SKR wrapped_blob format.");
            return "";
        }

        std::string skrResponsePayload = base64url_decode(skrResponseTokens[1]);
        json skrResponseJson = json::parse(skrResponsePayload.c_str());

        if (!skrResponseJson.contains("response") || !skrResponseJson["response"].contains("key") || !skrResponseJson["response"]["key"].contains("key") || !skrResponseJson["response"]["key"]["key"].contains("key_hsm"))
        {
            printf("Invalid SKR response structure.");
            return "";
        }

        std::string keyHsmBase64Url = skrResponseJson["response"]["key"]["key"]["key_hsm"].get<std::string>();
        std::string keyHsmJsonStr = base64url_decode(keyHsmBase64Url);
        json keyHsmJsonObj = json::parse(keyHsmJsonStr);

        if (!keyHsmJsonObj.contains("ciphertext"))
        {
            printf("Invalid keyHsmJson structure.");
            return "";
        }

        std::string ciphertext = keyHsmJsonObj["ciphertext"].get<std::string>();
        return ciphertext;
    }
};
