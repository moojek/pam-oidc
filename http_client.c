#include "http_client.h"
#include <stdlib.h>
#include <string.h>

static size_t cb(char* data, size_t size, size_t nmemb, void* clientp)
{
    size_t realsize = size * nmemb;
    struct response* resp = (struct response*)clientp;

    char* ptr = realloc(resp->body, resp->size + realsize + 1);
    if (!ptr)
        return 0; /* out of memory */

    resp->body = ptr;
    memcpy(&(resp->body[resp->size]), data, realsize);
    resp->size += realsize;
    resp->body[resp->size] = 0;

    return realsize;
}

CURLcode http_get(const char* url, struct response* response)
{
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);

        CURLcode res = curl_easy_perform(curl);

        curl_easy_cleanup(curl);
        return res;
    }

    return -1;
}

CURLcode http_get_with_bearer_token(const char* url, const char* bearer, struct response* response)
{
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearer);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);

        CURLcode res = curl_easy_perform(curl);

        curl_easy_cleanup(curl);
        return res;
    }

    return -1;
}

CURLcode http_get_with_bearer_token_and_parameter(const char* base_url, const char* bearer, const char* key, const char* value, struct response* response)
{
    fprintf(stderr, "start get k=%s v=%s\n", key, value);

    char* query = malloc(strlen(key) + strlen(value) + 1);
    strcpy(query, key);
    strcat(query, "=");
    strcat(query, value);

    CURLUcode rc;
    CURLU* url_builder = curl_url();
    rc = curl_url_set(url_builder, CURLUPART_URL, base_url, 0);
    if (rc) {
        fprintf(stderr, "url set failed (%d) for URL=%s\n", rc, base_url);
    }
    rc = curl_url_set(url_builder, CURLUPART_QUERY, query, CURLU_APPENDQUERY | CURLU_URLENCODE);
    if (rc) {
        fprintf(stderr, "url set failed (%d) for QUERY=%s\n", rc, query);
    }
    char* full_url;
    rc = curl_url_get(url_builder, CURLUPART_URL, &full_url, 0);
    if (rc) {
        fprintf(stderr, "url get failed (%d)\n", rc);
    }
    fprintf(stderr, "url get url=%s\n", full_url);

    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearer);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);

        fprintf(stderr, "GET %s\nBearer %s\n", full_url, bearer);
        CURLcode res = curl_easy_perform(curl);
        fprintf(stderr, "200 OK (or not)\n%s\n", response->body);

        curl_easy_cleanup(curl);
        return res;
    }

    return -1;
}

char* url_encode_form_data(const char* form_data)
{
    char* result = malloc(1);
    *result = 0;
    char* p = malloc(strlen(form_data) + 1);
    // fprintf(stderr, "1");
    strcpy(p, form_data);
    // fprintf(stderr, "2");
    CURL* curl = curl_easy_init();
    char* a = strtok(p, "&");
    // fprintf(stderr, "3\n");
    while (a) {
        // fprintf(stderr, "%s, %c\n", a, *a);
        char* e = strchr(a, '=');
        // fprintf(stderr, "while chr: %c\n", *e);
        char* encoded_key = curl_easy_escape(curl, a, e - a);
        char* encoded_value = curl_easy_escape(curl, e + 1, 0);
        // fprintf(stderr, "result before: %s\n", result);
        result = realloc(result, strlen(result) + strlen(encoded_key) + 1 + strlen(encoded_value) + 2);
        strcat(result, encoded_key);
        strcat(result, "=");
        strcat(result, encoded_value);
        strcat(result, "&");
        // fprintf(stderr, "result after: %s\n", result);
        a = strtok(NULL, "&");
    }
    result[strlen(result) - 1] = '\0';
    curl_easy_cleanup(curl);
    // fprintf(stderr, "0\n");
    return result;
}

CURLcode http_post(const char* url, const char* payload, struct response* response)
{
    CURL* curl = curl_easy_init();
    if (curl) {
        char* payload_url_encoded = url_encode_form_data(payload);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload_url_encoded);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);

        // fprintf(stderr, "POST %s\n%s\n\n", url, payload_url_encoded);
        CURLcode res = curl_easy_perform(curl);

        free(payload_url_encoded);
        curl_easy_cleanup(curl);
        return res;
    }

    return -1;
}