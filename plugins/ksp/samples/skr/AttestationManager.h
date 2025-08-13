//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationManager.h" company="Microsoft Corporation">
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

using json = nlohmann::json;

constexpr char DUMMY_MAA_ENDPOINT[] = "https://dummymanticoreattestationapp.azurewebsites.net/ManticoreAttest";

/**
 * @class AttestationManager
 * @brief Manages the attestation process by communicating with the Dummy MAA endpoint.
 */
class AttestationManager
{
public:
    /**
     * @brief Constructor for AttestationManager.
     * @param cert_chain The certificate chain.
     * @param attestation_claim The attestation claim.
     */
    AttestationManager(const std::string &cert_chain, const std::string &attestation_claim)
        : cert_chain_(cert_chain), attestation_claim_(attestation_claim)
    {
    }

    /**
     * @brief Retrieves the attestation token from the Dummy MAA endpoint.
     * @return A string containing the attestation token.
     */
    std::string GetAttestationToken()
    {
        HttpClient httpClient;
        httpClient.SetUrl(DUMMY_MAA_ENDPOINT);
        httpClient.SetTimeout(20L);

        struct curl_slist *headers = NULL;
        std::string content_type = "Content-Type: application/json";
        headers = curl_slist_append(headers, content_type.c_str());
        httpClient.SetHeaders(headers);

        httpClient.SetHttpMethod("POST");

        std::string payload = CreateAttestationPayload(cert_chain_, attestation_claim_);
        httpClient.SetPayload(payload);

        std::string response = "";
        bool bool_result = false;
        bool_result = httpClient.PerformRequest(response);
        if (!bool_result)
        {
            printf("Failed to get attestation token");
        }

        return response;
    }

private:
    std::string cert_chain_;
    std::string attestation_claim_;

    /**
     * @brief Creates the attestation payload to be sent to the Dummy MAA endpoint.
     * @param cert_chain The certificate chain.
     * @param attestation_claim The attestation claim.
     * @return A JSON string containing the attestation payload.
     */
    std::string CreateAttestationPayload(const std::string &cert_chain, const std::string &attestation_claim)
    {
        json root;
        root["manticore_report"] = attestation_claim;
        root["signing_cert"] = cert_chain;
        return root.dump();
    }
};
