//-------------------------------------------------------------------------------------------------
// <copyright file="MsiManager.h" company="Microsoft Corporation">
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
#include "ArgumentValidator.h"

using json = nlohmann::json;

constexpr char AKV_IMDS_MSI_URL[] = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3a%2f%2fvault.azure.net";
constexpr char MHSM_IMDS_MSI_URL[] = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3a%2f%2fmanagedhsm.azure.net";

/**
 * @class MsiManager
 * @brief Manages the retrieval of Managed Service Identity (MSI) tokens.
 */
class MsiManager
{
public:
    MsiManager() {}

    /**
     * @brief Retrieves an MSI token for the specified vault type.
     *
     * @param vaultType The type of vault (AKV or MHSM).
     * @return A string containing the MSI token.
     */
    std::string GetMsiToken(VaultType vaultType)
    {
        HttpClient httpClient;
        httpClient.SetUrl(GetIMDSEndpoint(vaultType));
        httpClient.SetTimeout(20L);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Metadata:true");
        httpClient.SetHeaders(headers);

        httpClient.SetHttpMethod("GET");

        std::string response = "";
        bool bool_result = false;
        bool_result = httpClient.PerformRequest(response);
        if (!bool_result)
        {
            printf("Failed to get MSI token");
        }

        json root = json::parse(response.c_str());

        std::string msi_token = root["access_token"].get<std::string>();

        return msi_token;
    }

private:
    /**
     * @brief Gets the IMDS endpoint URL for the specified vault type.
     *
     * @param vaultType The type of vault (AKV or MHSM).
     * @return A string containing the IMDS endpoint URL.
     */
    std::string GetIMDSEndpoint(VaultType vaultType)
    {
        switch (vaultType)
        {
        case VaultType::AKV:
            return AKV_IMDS_MSI_URL;
        case VaultType::MHSM:
            return MHSM_IMDS_MSI_URL;
        default:
            return ""; // return an empty string for unknown types
        }
    }
};
