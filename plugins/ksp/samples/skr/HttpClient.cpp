//-------------------------------------------------------------------------------------------------
// <copyright file="HttpClient.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <curl/curl.h>
#include <string>
#include <chrono>
#include <thread>
#include <math.h>
#include "HttpClient.h"

HttpClient::HttpClient()
{
    curl_ = curl_easy_init();
    if (curl_ == nullptr)
    {
        printf("Failed to initialize curl for HTTP request.");
    }
}

HttpClient::~HttpClient()
{
    if (curl_)
    {
        curl_easy_cleanup(curl_);
    }
}

void HttpClient::SetUrl(const std::string &url)
{
    url_ = url;
}

void HttpClient::SetHeaders(struct curl_slist *headers)
{
    curl_slist_free_all(headers_);
    headers_ = headers;
}

void HttpClient::SetTimeout(long timeout)
{
    timeout_ = timeout;
}

void HttpClient::SetPayload(const std::string &payload)
{
    payload_ = payload;
}

void HttpClient::SetHttpMethod(const std::string &http_method)
{
    http_method_ = http_method;
}

bool HttpClient::PerformRequest(std::string &response)
{
    if (!curl_)
    {
        printf("Failed to init curl");
        return false;
    }

    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers_);
    curl_easy_setopt(curl_, CURLOPT_URL, url_.c_str());

    if (http_method_ == "POST")
    {
        curl_easy_setopt(curl_, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, payload_.c_str());
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, payload_.size());
        curl_easy_setopt(curl_, CURLOPT_CAINFO, "curl-ca-bundle.crt");
    }

    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, timeout_);

    std::string result;
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteResponseCallback);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &result);

    CURLcode res = CURLE_OK;
    uint8_t retries = 0;
    while ((res = curl_easy_perform(curl_)) == CURLE_OK)
    {
        long response_code = HTTP_STATUS_OK;
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &response_code);

        if (response_code == HTTP_STATUS_OK)
        {
            // printf("Successfully received attestation token");
            response = result;
            break;
        }
        else if (response_code == HTTP_STATUS_THROTTLE_LIMIT ||
                 response_code >= HTTP_STATUS_TRANSIENT_ERRORS)
        {
            if (retries == MAX_RETRIES)
            {
                printf("Failed to get response. Maximum retries exceeded\n");
                break;
            }
            printf("Request failed with error code:%ld description:%s",
                   response_code,
                   response.c_str());
            printf("Retrying:%d", retries);
            std::this_thread::sleep_for(
                std::chrono::seconds(
                    static_cast<long long>(5 * pow(2.0, static_cast<double>(retries++)))));
            response = std::string();
            continue;
        }
        else
        {
            printf("Request failed with error code:%ld description:%s",
                   response_code,
                   result.c_str());
            break;
        }
    }

    if (res != CURLE_OK)
    {
        printf("Failed sending curl request with error:%s\n",
               curl_easy_strerror(res));
    }

    return true;
}
