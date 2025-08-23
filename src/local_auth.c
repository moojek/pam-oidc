#include "auth.h"
#include "http_client.h"

#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <security/pam_appl.h>

int authenticate_local(const char* username, const char* token)
{
    struct response verify_resp = { 0 };
    char* verify_query = "http://localhost:8080/verify_user";
    CURLcode code = http_get_with_bearer_token_and_parameter(verify_query, token, "username", username, &verify_resp);

    cJSON* json = cJSON_Parse(verify_resp.body);
    cJSON* verified_status_json = cJSON_GetObjectItemCaseSensitive(json, "verified");
    fprintf(stderr, "verified_status_json=%s\n", cJSON_GetStringValue(verified_status_json));
    if (!cJSON_IsTrue(verified_status_json))
        return PAM_AUTH_ERR;
    return PAM_SUCCESS;
    // char* verified_status = malloc(strlen(verified_status_json->valuestring) + 1);
    // strcpy(verified_status, verified_status_json->valuestring);
    // printf("verified = %s\n", verified_status);
}