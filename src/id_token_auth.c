#include "auth.h"
#include "http_client.h"

#include <cjson/cJSON.h>
#include <jwt.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

#define SIMPLE_SUB_MAPPER

#ifdef SIMPLE_SUB_MAPPER
void map_sub_to_username(const char* sub, char** username)
{
    fprintf(stderr, "sub in map: \"%s\"\n", sub);
    *username = malloc(strlen(sub) + 5);
    sprintf(*username, "user%s", sub);
}
#endif

int extract_sub(jwt_t* jwt, jwt_config_t* config)
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

void get_jwks_json_string(char** jwks_json_string, const char* openid_configuration_endpoint)
{
    *jwks_json_string = NULL;
    CURLcode curlcode;

    struct Response well_known_response = { 0 };
    if ((curlcode = get(openid_configuration_endpoint, &well_known_response)) != CURLE_OK)
        goto finish;

    cJSON* well_known_json = cJSON_Parse(well_known_response.body);
    if (!well_known_json)
        goto finish;

    cJSON* jwks_uri_json = cJSON_GetObjectItemCaseSensitive(well_known_json, "jwks_uri");
    char* jwks_uri = strdup(cJSON_GetStringValue(jwks_uri_json));
    if (!jwks_uri)
        goto finish;

    struct Response jwks_response = { 0 };
    if ((curlcode = get(jwks_uri, &jwks_response)) != CURLE_OK)
        goto finish;

    cJSON* jwks_json = cJSON_Parse(jwks_response.body);
    if (!jwks_json)
        goto finish;

    *jwks_json_string = cJSON_Print(jwks_json);

finish:
    if (well_known_response.body)
        free(well_known_response.body);
    if (well_known_json)
        cJSON_Delete(well_known_json);
    if (jwks_uri)
        free(jwks_uri);
    if (jwks_response.body)
        free(jwks_response.body);
    if (jwks_json)
        cJSON_Delete(jwks_json);
}

#ifndef OPENID_CONFIGURATION_ENDPOINT
#define OPENID_CONFIGURATION_ENDPOINT "https://accounts.google.com/.well-known/openid-configuration"
#endif

int authenticate_id_token(const char* username, const char* id_token, const char* openid_configuration_endpoint)
{
    int retval = PAM_AUTH_ERR;
    char* mapped_username;
    char* sub;
    int verification = 1;

    jwt_checker_t* jwt_checker;
    if ((jwt_checker = jwt_checker_new()) == NULL) {
        retval = PAM_AUTH_ERR;
        goto finish;
    }

    char* jwks_json_string;
    get_jwks_json_string(&jwks_json_string,
        openid_configuration_endpoint ? openid_configuration_endpoint : OPENID_CONFIGURATION_ENDPOINT);
    if (!jwks_json_string) {
        retval = PAM_AUTH_ERR;
        goto finish;
    }

    jwk_set_t* jwks = jwks_load(NULL, jwks_json_string);
    if (!jwks || jwks_error_any(jwks)) {
        retval = PAM_AUTH_ERR;
        goto finish;
    }
    for (size_t i = 0; i < jwks_item_count(jwks); i++) {
        fprintf(stderr, "Trying to verify JWT with JWK %s\n", jwks_item_kid(jwks_item_get(jwks, i)));
        if (jwt_checker_setkey(jwt_checker, JWT_ALG_RS256, jwks_item_get(jwks, i)))
            continue;
        if (jwt_checker_setcb(jwt_checker, &extract_sub, &sub))
            continue;
        verification = jwt_checker_verify(jwt_checker, id_token);
        fprintf(stderr, "Verification result: %d\n", verification);
        if (!verification)
            break;
    }

    if (verification) {
        fprintf(stderr, "JWT verification failed with status %d and message '%s'\n", verification, jwt_checker_error_msg(jwt_checker));
        retval = PAM_AUTH_ERR;
        goto finish;
    }

    map_sub_to_username(sub, &mapped_username);
    if (strcmp(username, mapped_username)) {
        fprintf(stderr, "Username %s does not match mapped username %s\n", username, mapped_username);
        retval = PAM_AUTH_ERR;
        goto finish;
    }
    retval = PAM_SUCCESS;

finish:
    if (jwt_checker)
        jwt_checker_free(jwt_checker);
    if (jwks_json_string)
        free(jwks_json_string);
    if (jwks)
        jwks_free(jwks);
    if (sub)
        free(sub);
    if (mapped_username)
        free(mapped_username);

    return retval;
}