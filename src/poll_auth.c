#include "auth.h"
#include "http_client.h"

#include <cjson/cJSON.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef OPENID_CONFIGURATION_ENDPOINT
#define OPENID_CONFIGURATION_ENDPOINT "https://accounts.google.com/.well-known/openid-configuration"
#endif
#ifndef CLIENT_ID
#define CLIENT_ID NULL
#endif
#ifndef CLIENT_SECRET
#define CLIENT_SECRET NULL
#endif

int authenticate_poll(const char* username, void (*prompt_callback)(const char*, void*), void* prompt_context,
    const char* openid_configuration_endpoint, const char* client_id, const char* client_secret)
{
    int retval = PAM_AUTH_ERR;
    CURLcode curlcode;

    client_id = client_id ? client_id : CLIENT_ID;
    client_secret = client_secret ? client_secret : CLIENT_SECRET;
    if (client_id == NULL || client_secret == NULL)
        goto end;

    struct response well_known_response = { 0 };
    openid_configuration_endpoint
        = openid_configuration_endpoint ? openid_configuration_endpoint : OPENID_CONFIGURATION_ENDPOINT;
    if ((curlcode = http_get(openid_configuration_endpoint, &well_known_response)) != CURLE_OK)
        goto end;

    cJSON* well_known_json = cJSON_Parse(well_known_response.body);
    if (!well_known_json)
        goto end;

    cJSON* device_auth_endpoint_json
        = cJSON_GetObjectItemCaseSensitive(well_known_json, "device_authorization_endpoint");
    char* device_auth_endpoint = strdup(cJSON_GetStringValue(device_auth_endpoint_json));
    if (!device_auth_endpoint)
        goto end;

    char* payload = malloc(strlen(client_id) + 31);
    if (!payload)
        goto end;
    sprintf(payload, "client_id=%s&scope=email profile", client_id);

    struct response auth_start_resp = { 0 };
    if ((curlcode = http_post(device_auth_endpoint, payload, &auth_start_resp)) != CURLE_OK)
        goto end;

    cJSON* auth_start_resp_json = cJSON_Parse(auth_start_resp.body);
    char* verification_url
        = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "verification_url"));
    char* user_code = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "user_code"));
    char* prompt = malloc(strlen(verification_url) + strlen(user_code) + 44);
    if (!prompt)
        goto end;
    sprintf(prompt, "Continue by visiting %s and using code %s there", verification_url, user_code);
    prompt_callback(prompt, prompt_context);

    char* device_code = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "device_code"));
    char* payload2 = malloc(strlen(client_id) + strlen(client_secret) + strlen(device_code) + 82);
    if (!payload2)
        goto end;
    sprintf(payload2, "client_id=%s&client_secret=%s&code=%s&grant_type=http://oauth.net/grant_type/device/1.0",
        client_id, client_secret, device_code);
    int delay = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "interval"));
    int expiry = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "expires_in"));
    int current_wait_time = 0;
    char* token = NULL;
    while (current_wait_time <= expiry) {
        struct response response = { 0 };
        if ((curlcode = http_post("https://oauth2.googleapis.com/token", payload2, &response)) != CURLE_OK) {
            if (response.body)
                free(response.body);
            goto end;
        }

        fprintf(stderr, "poll response: %s\n", response.body);
        cJSON* poll_resp_json = cJSON_Parse(response.body);
        if (!poll_resp_json) {
            if (response.body)
                free(response.body);
            goto end;
        }

        if (cJSON_HasObjectItem(poll_resp_json, "error")) {
            char* error = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(poll_resp_json, "error"));
            fprintf(stderr, "Poll error: %s\n", error);
            if (!strcmp(error, "slow_down")) {
                delay++;
            }
            // free(error);
        } else {
            token = strdup(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(poll_resp_json, "id_token")));
            fprintf(stderr, "Token: %s\n", token);
        }

        free(response.body);
        cJSON_Delete(poll_resp_json);

        if (token)
            break;

        sleep(delay);
    }
    if (token == NULL)
        goto end;

    retval = authenticate_id_token(username, token, openid_configuration_endpoint);

end:
    if (well_known_response.body)
        free(well_known_response.body);
    if (well_known_json)
        cJSON_Delete(well_known_json);
    if (device_auth_endpoint)
        free(device_auth_endpoint);
    if (payload)
        free(payload);
    if (auth_start_resp.body)
        free(auth_start_resp.body);
    if (auth_start_resp_json)
        cJSON_Delete(auth_start_resp_json);
    if (prompt)
        free(prompt);
    if (payload2)
        free(payload2);
    if (token)
        free(token);
    return retval;
}