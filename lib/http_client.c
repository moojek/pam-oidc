#include "http_client.h"
#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

static size_t callback(char* data, size_t size, size_t nmemb, void* clientp)
{
    size_t realsize = size * nmemb;
    struct Response* resp = (struct Response*)clientp;

    char* ptr = realloc(resp->body, resp->size + realsize + 1);
    if (!ptr)
        return 0;

    resp->body = ptr;
    memcpy(&(resp->body[resp->size]), data, realsize);
    resp->size += realsize;
    resp->body[resp->size] = 0;

    return realsize;
}

int get(const char* url, struct Response* response)
{
    int returnValue = 1;

    CURL* curl = curl_easy_init();
    if (!curl)
        goto finish;

    CURLcode curlReturnValue;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_perform(curl)) != CURLE_OK)
        goto finish;
    returnValue = 0;

finish:
    if (curl)
        curl_easy_cleanup(curl);
    return returnValue;
}

cJSON* getAsJSON(const char* url)
{
    struct Response response = { 0 };
    if (get(url, &response))
        return NULL;

    cJSON* json = NULL;
    if (response.body) {
        json = cJSON_Parse(response.body);
        free(response.body);
    }
    return json;
}

int getWithBearerToken(const char* url, const char* bearerToken, struct Response* response)
{
    int returnValue = 1;

    CURL* curl = curl_easy_init();
    if (!curl)
        goto finish;

    CURLcode curlReturnValue;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearerToken)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_perform(curl)) != CURLE_OK)
        goto finish;
    returnValue = 0;

finish:
    if (curl)
        curl_easy_cleanup(curl);
    return returnValue;
}

cJSON* getWithBearerTokenAsJSON(const char* url, const char* bearerToken)
{
    struct Response response = { 0 };
    if (getWithBearerToken(url, bearerToken, &response))
        return NULL;

    cJSON* json = NULL;
    if (response.body) {
        json = cJSON_Parse(response.body);
        free(response.body);
    }
    return json;
}

int getWithBearerTokenAndSingleParameter(
    const char* baseURL, const char* bearerToken, const char* key, const char* value, struct Response* response)
{
    int returnValue = 1;

    fprintf(stderr, "start get k=%s v=%s\n", key, value);

    char* query = malloc(strlen(key) + strlen(value) + 1);
    if (!query)
        goto finish;
    strcpy(query, key);
    strcat(query, "=");
    strcat(query, value);

    CURLU* urlBuilder = curl_url();
    if (!urlBuilder)
        goto finish;

    char* url;
    CURLUcode urlBuilderReturnValue;
    if ((urlBuilderReturnValue = curl_url_set(urlBuilder, CURLUPART_URL, baseURL, 0)) != CURLUE_OK) {
        fprintf(stderr, "url set failed (%d) for URL=%s\n", urlBuilderReturnValue, baseURL);
        goto finish;
    }
    if ((urlBuilderReturnValue = curl_url_set(urlBuilder, CURLUPART_QUERY, query, CURLU_APPENDQUERY | CURLU_URLENCODE))
        != CURLUE_OK) {
        fprintf(stderr, "url set failed (%d) for QUERY=%s\n", urlBuilderReturnValue, query);
        goto finish;
    }
    if ((urlBuilderReturnValue = curl_url_get(urlBuilder, CURLUPART_URL, &url, 0)) != CURLUE_OK) {
        fprintf(stderr, "url get failed (%d)\n", urlBuilderReturnValue);
        goto finish;
    }
    fprintf(stderr, "url get url=%s\n", url);

    CURL* curl = curl_easy_init();
    if (!curl)
        goto finish;

    CURLcode curlReturnValue;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearerToken)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback)) != CURLE_OK)
        goto finish;
    if ((curlReturnValue = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response)) != CURLE_OK)
        goto finish;
    fprintf(stderr, "GET %s\nBearer %s\n", url, bearerToken);
    if ((curlReturnValue = curl_easy_perform(curl)) != CURLE_OK)
        goto finish;
    fprintf(stderr, "200 OK (or not)\n%s\n", response->body);
    returnValue = 0;

finish:
    if (query)
        free(query);
    if (urlBuilder)
        curl_url_cleanup(urlBuilder);
    if (curl)
        curl_easy_cleanup(curl);
    return returnValue;
}

cJSON* getWithBearerTokenAndSingleParameterAsJSON(
    const char* baseUrl, const char* bearerToken, const char* key, const char* value)
{
    struct Response response = { 0 };
    if (getWithBearerTokenAndSingleParameter(baseUrl, bearerToken, key, value, &response))
        return NULL;

    cJSON* json = NULL;
    if (response.body) {
        json = cJSON_Parse(response.body);
        free(response.body);
    }
    return json;
}

char* urlEncodeFormData(const char* formData)
{
    char* returnValue = NULL;

    char* formDataCopy = strdup(formData);
    if (!formDataCopy)
        goto finish;

    char* encodedFormData = malloc(1);
    if (!encodedFormData)
        goto finish;
    *encodedFormData = '\0';

    char* atSignPtr = strtok(formDataCopy, "&");
    while (atSignPtr) {
        char* equalSignPtr = strchr(atSignPtr, '=');
        if (!equalSignPtr)
            goto finish;

        char* encodedKey = curl_easy_escape(NULL, atSignPtr, equalSignPtr - atSignPtr);
        char* encodedValue = curl_easy_escape(NULL, equalSignPtr + 1, 0);
        if (!encodedKey || !encodedValue)
            goto finish;

        encodedFormData
            = realloc(encodedFormData, strlen(encodedFormData) + strlen(encodedKey) + 1 + strlen(encodedValue) + 2);
        if (!encodedFormData)
            goto finish;

        strcat(encodedFormData, encodedKey);
        strcat(encodedFormData, "=");
        strcat(encodedFormData, encodedValue);
        strcat(encodedFormData, "&");

        atSignPtr = strtok(NULL, "&");
    }
    encodedFormData[strlen(encodedFormData) - 1] = '\0';
    returnValue = encodedFormData;

finish:
    if (formDataCopy)
        free(formDataCopy);
    if (!returnValue && encodedFormData)
        free(encodedFormData);
    return returnValue;
}

int post(const char* url, const char* payload, struct Response* response)
{
    int returnValue = 1;

    char* payloadURLEncoded = urlEncodeFormData(payload);
    if (!payloadURLEncoded)
        goto finish;

    CURL* curl = curl_easy_init();
    if (!curl)
        goto finish;

    CURLcode retval;
    if ((retval = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadURLEncoded)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_perform(curl)) != CURLE_OK)
        goto finish;
    returnValue = 0;

finish:
    if (payloadURLEncoded)
        free(payloadURLEncoded);
    if (curl)
        curl_easy_cleanup(curl);
    return retval;
}

cJSON* postAsJSON(const char* url, const char* payload)
{
    struct Response response = { 0 };
    if (post(url, payload, &response))
        return NULL;

    cJSON* json = NULL;
    if (response.body) {
        json = cJSON_Parse(response.body);
        free(response.body);
    }
    return json;
}