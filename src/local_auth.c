#include "auth.h"
#include "../lib/http_client.h"

#include <cjson/cJSON.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef VERIFY_ENDPOINT
#define VERIFY_ENDPOINT "http://localhost:8080/verify_user"
#endif

int authenticateWithMotleyCue(const char* username, const char* token, const char* verificationEndpoint)
{
    int returnValue = PAM_AUTH_ERR;

    verificationEndpoint = verificationEndpoint ? verificationEndpoint : VERIFY_ENDPOINT;
    cJSON* verificationRequestJSON
        = getWithBearerTokenAndSingleParameterAsJSON(verificationEndpoint, token, "username", username);
    if (!verificationRequestJSON) {
        returnValue = PAM_AUTH_ERR;
        goto finish;
    }

    cJSON* verificationStatusJSON = cJSON_GetObjectItemCaseSensitive(verificationRequestJSON, "verified");
    fprintf(stderr, "verified_status_json=%s\n", cJSON_GetStringValue(verificationStatusJSON));
    if (!cJSON_IsTrue(verificationStatusJSON)) {
        returnValue = PAM_AUTH_ERR;
        goto finish;
    }

    returnValue = PAM_SUCCESS;

finish:
    if (verificationRequestJSON)
        cJSON_Delete(verificationRequestJSON);
    return returnValue;
}