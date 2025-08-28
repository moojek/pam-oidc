#include "auth.h"
#include "http_client.h"

#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <security/pam_appl.h>
#include <stdlib.h>

#ifndef VERIFY_ENDPOINT
#define VERIFY_ENDPOINT "http://localhost:8080/verify_user"
#endif

int authenticate_local(const char* username, const char* token, const char* verify_endpoint)
{
    int retval = PAM_AUTH_ERR;

    struct response verify_resp = { 0 };
    verify_endpoint = verify_endpoint ? verify_endpoint : VERIFY_ENDPOINT;
    CURLcode code = http_get_with_bearer_token_and_parameter(verify_endpoint, token, "username", username, &verify_resp);
    if (code != CURLE_OK) {
        retval = PAM_AUTH_ERR;
        goto finish;
    }

    cJSON* json = cJSON_Parse(verify_resp.body);
    if (!json) {
        retval = PAM_AUTH_ERR;
        goto finish;
    }
    cJSON* verified_status_json = cJSON_GetObjectItemCaseSensitive(json, "verified");
    fprintf(stderr, "verified_status_json=%s\n", cJSON_GetStringValue(verified_status_json));
    if (!cJSON_IsTrue(verified_status_json)) {
        retval = PAM_AUTH_ERR;
        goto finish;
    }

    retval = PAM_SUCCESS;

finish:
    if (verify_resp.body)
        free(verify_resp.body);
    if (json)
        cJSON_Delete(json);
    return retval;
}