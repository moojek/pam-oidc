#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <curl/curl.h>

struct Response {
    size_t size;
    char* body;
};

int get(const char* url, struct Response* response);
int getWithBearerToken(const char* url, const char* bearer, struct Response* response);
int getWithBearerTokenAndSingleParameter(
    const char* baseUrl, const char* bearer, const char* key, const char* value, struct Response* response);
int post(const char* url, const char* payload, struct Response* response);

#endif // HTTP_CLIENT_H