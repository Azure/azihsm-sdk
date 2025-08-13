//-------------------------------------------------------------------------------------------------
// <copyright file="AadTokenManager.h" company="Microsoft Corporation">
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

/**
 * @class AadTokenManager
 * @brief Manages the retrieval of Azure Active Directory (AAD) tokens.
 */
class AadTokenManager
{
public:
    AadTokenManager() {}

    /**
     * @brief Retrieves an AAD token for the specified vault type.
     *
     * @param vaultType The type of vault (AKV or MHSM).
     * @param appId The application ID for AAD authentication.
     * @param secret The client secret for AAD authentication.
     * @return A string containing the AAD token.
     */
    std::string GetAadToken(
        VaultType vaultType,
        const std::string &appId,
        const std::string &secret)
    {
        HttpClient httpClient;
        httpClient.SetUrl("https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/token");
        httpClient.SetTimeout(20L);

        struct curl_slist *headers = NULL;
        httpClient.SetHeaders(headers);

        httpClient.SetHttpMethod("POST");
        std::string resType = vaultType == VaultType::AKV ? "https://vault.azure.net" : "https://managedhsm.azure.net";
        std::string post_fields = "grant_type=client_credentials&client_id=" + appId + "&client_secret=" + secret + "&resource=" + resType;
        httpClient.SetPayload(post_fields);

        std::string response = "";
        bool bool_result = false;
        bool_result = httpClient.PerformRequest(response);
        if (!bool_result)
        {
            printf("Failed to retrieve AAD token");
        }

        json root = json::parse(response.c_str());
        std::string msi_token = root["access_token"].get<std::string>();
        return msi_token;
    }
};
