#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <curl/curl.h>

struct response {
    size_t size;
    char* body;
};

CURLcode http_get(const char* url, struct response* response);
CURLcode http_get_with_bearer_token(const char* url, const char* bearer, struct response* response);
CURLcode http_get_with_bearer_token_and_parameter(const char* base_url, const char* bearer, const char* key, const char* value, struct response* response);
CURLcode http_post(const char* url, const char* payload, struct response* response);

#endif // HTTP_CLIENT_H