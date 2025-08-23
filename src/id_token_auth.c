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
    jwt_value_t sub_claim;
    jwt_set_GET_STR(&sub_claim, "sub");
    jwt_claim_get(jwt, &sub_claim);
    fprintf(stderr, "sub: \"%s\"\n", sub_claim.str_val);
    *((char**)config->ctx) = strdup(sub_claim.str_val);
    return 0;
}

void get_jwks_json(char** jwks)
{
    struct response well_known_response = { 0 };
    http_get("https://accounts.google.com/.well-known/openid-configuration", &well_known_response);

    cJSON* well_known_json = cJSON_Parse(well_known_response.body);
    cJSON* jwks_uri_json = cJSON_GetObjectItemCaseSensitive(well_known_json, "jwks_uri");
    char* jwks_uri = strdup(cJSON_GetStringValue(jwks_uri_json));
    cJSON_Delete(well_known_json);

    struct response jwks_response = { 0 };
    http_get(jwks_uri, &jwks_response);
    cJSON* jwks_json = cJSON_Parse(jwks_response.body);
    *jwks = cJSON_Print(jwks_json);
    cJSON_Delete(jwks_json);
}

int authenticate_id_token(const char* username, const char* id_token)
{
    int status = PAM_AUTH_ERR;
    char* mapped_username;
    char* sub;
    int verification = 1;

    jwt_checker_t* jwt_checker = jwt_checker_new();
    char* jwks_json;
    get_jwks_json(&jwks_json);
    jwk_set_t* jwks = jwks_load(NULL, jwks_json);
    for (size_t i = 0; i < jwks_item_count(jwks); i++) {
        fprintf(stderr, "Trying to verify JWT with JWK %s\n", jwks_item_kid(jwks_item_get(jwks, i)));
        jwt_checker_setkey(jwt_checker, JWT_ALG_RS256, jwks_item_get(jwks, i));
        jwt_checker_setcb(jwt_checker, &extract_sub, &sub);
        verification = jwt_checker_verify(jwt_checker, id_token);
        fprintf(stderr, "Verification result: %d\n", verification);
        if (!verification)
            break;
    }

    if (verification) {
        fprintf(stderr, "JWT verification failed with status %d and message '%s'\n", verification, jwt_checker_error_msg(jwt_checker));
        status = PAM_AUTH_ERR;
        goto finish;
    }

    map_sub_to_username(sub, &mapped_username);
    if (strcmp(username, mapped_username)) {
        fprintf(stderr, "Username %s does not match mapped username %s\n", username, mapped_username);
        status = PAM_AUTH_ERR;
        goto finish;
    }

    status = PAM_SUCCESS;

finish:
    if (jwt_checker)
        jwt_checker_free(jwt_checker);
    if (sub)
        free(sub);

    return status;
}