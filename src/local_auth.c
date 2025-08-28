#include "auth.h"
#include "http_client.h"

#include <cjson/cJSON.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef VERIFY_ENDPOINT
#define VERIFY_ENDPOINT "http://localhost:8080/verify_user"
#endif

int authenticate_local(const char* username, const char* token, const char* verify_endpoint)
{
    int retval = PAM_AUTH_ERR;

    verify_endpoint = verify_endpoint ? verify_endpoint : VERIFY_ENDPOINT;
    cJSON* verify_req_json = getWithBearerTokenAndSingleParameterAsJSON(verify_endpoint, token, "username", username);
    if (!verify_req_json) {
        retval = PAM_AUTH_ERR;
        goto finish;
    }

    cJSON* verified_status_json = cJSON_GetObjectItemCaseSensitive(verify_req_json, "verified");
    fprintf(stderr, "verified_status_json=%s\n", cJSON_GetStringValue(verified_status_json));
    if (!cJSON_IsTrue(verified_status_json)) {
        retval = PAM_AUTH_ERR;
        goto finish;
    }

    retval = PAM_SUCCESS;

finish:
    if (verify_req_json)
        cJSON_Delete(verify_req_json);
    return retval;
}