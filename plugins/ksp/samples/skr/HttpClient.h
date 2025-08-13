//-------------------------------------------------------------------------------------------------
// <copyright file="HttpClient.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <curl/curl.h>
#include <string>

#define HTTP_STATUS_OK 200
#define HTTP_STATUS_THROTTLE_LIMIT 429
#define HTTP_STATUS_TRANSIENT_ERRORS 500
#define MAX_RETRIES 3

class HttpClient
{
public:
    HttpClient();
    ~HttpClient();

    void SetUrl(const std::string &url);
    void SetHeaders(struct curl_slist *headers);
    void SetTimeout(long timeout);
    void SetPayload(const std::string &payload);
    void SetHttpMethod(const std::string &http_method);

    bool PerformRequest(std::string &response);

private:
    CURL *curl_;
    struct curl_slist *headers_;
    std::string url_;
    std::string payload_;
    std::string http_method_ = "GET";
    long timeout_ = 20L;

    static size_t WriteResponseCallback(void *contents, size_t size, size_t nmemb, void *response)
    {
        if (response == nullptr || contents == nullptr)
        {
            printf("Invalid input parameters");
            return 0;
        }
        std::string *responsePtr = reinterpret_cast<std::string *>(response);

        char *contentsStr = static_cast<char *>(contents);
        size_t contentsSize = size * nmemb;

        responsePtr->insert(responsePtr->end(), contentsStr, contentsStr + contentsSize);

        return contentsSize;
    }
};
