#include "auth.h"
#include "../lib/http_client.h"

#include <cjson/cJSON.h>
#include <jwt.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

#define SIMPLE_SUB_MAPPER

#ifdef SIMPLE_SUB_MAPPER
void mapSubClaimToUsername(const char* sub, char** username)
{
    fprintf(stderr, "sub in map: \"%s\"\n", sub);
    *username = malloc(strlen(sub) + 5);
    sprintf(*username, "user%s", sub);
}
#endif

int extractSubClaim(jwt_t* jwt, jwt_config_t* config)
{
    *((char**)config->ctx) = NULL;

    jwt_value_t sub_claim;
    jwt_set_GET_STR(&sub_claim, "sub");

    jwt_value_error_t retval;
    if ((retval = jwt_claim_get(jwt, &sub_claim)) != JWT_VALUE_ERR_NONE)
        return 1;
    fprintf(stderr, "sub: \"%s\"\n", sub_claim.str_val);

    *((char**)config->ctx) = strdup(sub_claim.str_val);
    return *((char**)config->ctx) == NULL;
}

void getJwksJsonString(char** jwksJsonString, const char* openidConfigurationEndpoint)
{
    *jwksJsonString = NULL;

    cJSON* openidConfigurationJson = getAsJSON(openidConfigurationEndpoint);
    if (!openidConfigurationJson)
        goto finish;

    cJSON* jwks_uri_json = cJSON_GetObjectItemCaseSensitive(openidConfigurationJson, "jwks_uri");
    char* jwksURI = strdup(cJSON_GetStringValue(jwks_uri_json));
    if (!jwksURI)
        goto finish;

    cJSON* jwksJSON = getAsJSON(jwksURI);
    if (!jwksJSON)
        goto finish;

    *jwksJsonString = cJSON_Print(jwksJSON);

finish:
    if (openidConfigurationJson)
        cJSON_Delete(openidConfigurationJson);
    if (jwksURI)
        free(jwksURI);
    if (jwksJSON)
        cJSON_Delete(jwksJSON);
}

#ifndef OPENID_CONFIGURATION_ENDPOINT
#define OPENID_CONFIGURATION_ENDPOINT "https://accounts.google.com/.well-known/openid-configuration"
#endif

int authenticateWithIDToken(const char* username, const char* idToken, const char* openidConfigurationEndpoint)
{
    int retval = PAM_AUTH_ERR;
    char* mappedUsername = NULL;
    char* sub = NULL;
    jwt_checker_t* jwtChecker = NULL;
    char* jwksJsonString = NULL;
    jwk_set_t* jwks = NULL;
    int jwtVerificationStatus;

    if (!(jwtChecker = jwt_checker_new())) {
        retval = PAM_AUTH_ERR;
        goto end;
    }

    getJwksJsonString(
        &jwksJsonString, openidConfigurationEndpoint ? openidConfigurationEndpoint : OPENID_CONFIGURATION_ENDPOINT);
    if (!jwksJsonString) {
        retval = PAM_AUTH_ERR;
        goto end;
    }

    jwks = jwks_load(NULL, jwksJsonString);
    if (!jwks || jwks_error_any(jwks)) {
        retval = PAM_AUTH_ERR;
        goto end;
    }

    for (size_t i = 0; i < jwks_item_count(jwks); i++) {
        fprintf(stderr, "Trying to verify JWT with JWK %s\n", jwks_item_kid(jwks_item_get(jwks, i)));
        if (jwt_checker_setkey(jwtChecker, JWT_ALG_RS256, jwks_item_get(jwks, i)))
            continue;
        if (jwt_checker_setcb(jwtChecker, &extractSubClaim, &sub))
            continue;
        jwtVerificationStatus = jwt_checker_verify(jwtChecker, idToken);
        fprintf(stderr, "Verification result: %d\n", jwtVerificationStatus);
        if (!jwtVerificationStatus)
            break;
    }

    if (jwtVerificationStatus) {
        fprintf(stderr, "JWT verification failed with status %d and message '%s'\n", jwtVerificationStatus,
            jwt_checker_error_msg(jwtChecker));
        retval = PAM_AUTH_ERR;
        goto end;
    }

    mapSubClaimToUsername(sub, &mappedUsername);
    if (strcmp(username, mappedUsername)) {
        fprintf(stderr, "Username %s does not match mapped username %s\n", username, mappedUsername);
        retval = PAM_AUTH_ERR;
        goto end;
    }
    retval = PAM_SUCCESS;

end:
    if (jwtChecker)
        jwt_checker_free(jwtChecker);
    if (jwksJsonString)
        free(jwksJsonString);
    if (jwks)
        jwks_free(jwks);
    if (sub)
        free(sub);
    if (mappedUsername)
        free(mappedUsername);

    return retval;
}