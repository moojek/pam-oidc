#include "http_client.h"
#include <stdlib.h>
#include <string.h>

static size_t cb(char* data, size_t size, size_t nmemb, void* clientp)
{
    size_t realsize = size * nmemb;
    struct response* resp = (struct response*)clientp;

    char* ptr = realloc(resp->body, resp->size + realsize + 1);
    if (!ptr)
        return 0;

    resp->body = ptr;
    memcpy(&(resp->body[resp->size]), data, realsize);
    resp->size += realsize;
    resp->body[resp->size] = 0;

    return realsize;
}

CURLcode http_get(const char* url, struct response* response)
{
    CURLcode retval = -1;

    CURL* curl = curl_easy_init();
    if (!curl)
        goto finish;

    if ((retval = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response)) != CURLE_OK)
        goto finish;
    retval = curl_easy_perform(curl);

finish:
    if (curl)
        curl_easy_cleanup(curl);
    return retval;
}

CURLcode http_get_with_bearer_token(const char* url, const char* bearer, struct response* response)
{
    CURLcode retval = -1;

    CURL* curl = curl_easy_init();
    if (!curl)
        goto finish;

    if ((retval = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearer)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response)) != CURLE_OK)
        goto finish;
    retval = curl_easy_perform(curl);

finish:
    if (curl)
        curl_easy_cleanup(curl);
    return retval;
}

CURLcode http_get_with_bearer_token_and_parameter(const char* base_url, const char* bearer, const char* key, const char* value, struct response* response)
{
    CURLcode retval = -1;

    fprintf(stderr, "start get k=%s v=%s\n", key, value);

    char* query = malloc(strlen(key) + strlen(value) + 1);
    if (!query)
        goto finish;
    strcpy(query, key);
    strcat(query, "=");
    strcat(query, value);

    CURLU* url_builder = curl_url();
    if (!url_builder)
        goto finish;

    char* full_url;
    CURLUcode rc;
    if ((rc = curl_url_set(url_builder, CURLUPART_URL, base_url, 0)) != CURLUE_OK) {
        fprintf(stderr, "url set failed (%d) for URL=%s\n", rc, base_url);
        goto finish;
    }
    if ((rc = curl_url_set(url_builder, CURLUPART_QUERY, query, CURLU_APPENDQUERY | CURLU_URLENCODE)) != CURLUE_OK) {
        fprintf(stderr, "url set failed (%d) for QUERY=%s\n", rc, query);
        goto finish;
    }
    if ((rc = curl_url_get(url_builder, CURLUPART_URL, &full_url, 0)) != CURLUE_OK) {
        fprintf(stderr, "url get failed (%d)\n", rc);
        goto finish;
    }
    fprintf(stderr, "url get url=%s\n", full_url);

    CURL* curl = curl_easy_init();
    if (!curl)
        goto finish;

    if ((retval = curl_easy_setopt(curl, CURLOPT_URL, full_url)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, bearer)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response)) != CURLE_OK)
        goto finish;
    fprintf(stderr, "GET %s\nBearer %s\n", full_url, bearer);
    retval = curl_easy_perform(curl);
    fprintf(stderr, "200 OK (or not)\n%s\n", response->body);

finish:
    if (query)
        free(query);
    if (url_builder)
        curl_url_cleanup(url_builder);
    if (curl)
        curl_easy_cleanup(curl);
    return retval;
}

char* url_encode_form_data(const char* form_data)
{
    char* retval = NULL;

    char* form_data_copy = malloc(strlen(form_data) + 1);
    if (!form_data_copy)
        goto finish;
    strcpy(form_data_copy, form_data);

    CURL* curl = curl_easy_init();
    if (!curl)
        goto finish;

    char* encoded_form_data = malloc(1);
    if (!encoded_form_data)
        goto finish;
    *encoded_form_data = 0;

    char* atsign_ptr = strtok(form_data_copy, "&");
    while (atsign_ptr) {
        char* eqsign_ptr = strchr(atsign_ptr, '=');
        if (!eqsign_ptr)
            goto finish;

        char* encoded_key = curl_easy_escape(curl, atsign_ptr, eqsign_ptr - atsign_ptr);
        char* encoded_value = curl_easy_escape(curl, eqsign_ptr + 1, 0);
        if (!encoded_key || !encoded_value)
            goto finish;

        encoded_form_data = realloc(encoded_form_data, strlen(encoded_form_data) + strlen(encoded_key) + 1 + strlen(encoded_value) + 2);
        if (!encoded_form_data)
            goto finish;

        strcat(encoded_form_data, encoded_key);
        strcat(encoded_form_data, "=");
        strcat(encoded_form_data, encoded_value);
        strcat(encoded_form_data, "&");

        atsign_ptr = strtok(NULL, "&");
    }
    encoded_form_data[strlen(encoded_form_data) - 1] = '\0';
    retval = encoded_form_data;

finish:
    if (form_data_copy)
        free(form_data_copy);
    if (curl)
        curl_easy_cleanup(curl);
    if (!retval && encoded_form_data)
        free(encoded_form_data);
    return retval;
}

CURLcode http_post(const char* url, const char* payload, struct response* response)
{
    CURLcode retval = -1;

    CURL* curl = curl_easy_init();
    if (!curl)
        goto finish;

    char* payload_url_encoded = url_encode_form_data(payload);
    if (!payload_url_encoded)
        goto finish;

    if ((retval = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload_url_encoded)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb)) != CURLE_OK)
        goto finish;
    if ((retval = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response)) != CURLE_OK)
        goto finish;
    retval = curl_easy_perform(curl);

finish:
    if (curl)
        curl_easy_cleanup(curl);
    if (payload_url_encoded)
        free(payload_url_encoded);
    return retval;
}