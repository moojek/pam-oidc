#include "auth.h"
#include "http_client.h"

#include <cjson/cJSON.h>
#include <math.h>
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

void get_openid_configuration(
    const char* openid_configuration_endpoint, char** device_auth_endpoint_ptr, char** token_endpoint_ptr)
{
    CURLcode curlcode;
    *device_auth_endpoint_ptr = NULL;
    *token_endpoint_ptr = NULL;

    struct response openid_configuration_resp = { 0 };
    if ((curlcode = http_get(openid_configuration_endpoint, &openid_configuration_resp)) != CURLE_OK)
        goto end;

    cJSON* openid_configuration_resp_json = cJSON_Parse(openid_configuration_resp.body);
    if (!openid_configuration_resp_json)
        goto end;

    char* device_auth_endpoint = cJSON_GetStringValue(
        cJSON_GetObjectItemCaseSensitive(openid_configuration_resp_json, "device_authorization_endpoint"));
    if (!device_auth_endpoint)
        goto end;
    *device_auth_endpoint_ptr = strdup(device_auth_endpoint);

    char* token_endpoint
        = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(openid_configuration_resp_json, "token_endpoint"));
    if (!token_endpoint)
        goto end;
    *token_endpoint_ptr = strdup(token_endpoint);

end:
    if (openid_configuration_resp.body)
        free(openid_configuration_resp.body);
    if (openid_configuration_resp_json)
        cJSON_Delete(openid_configuration_resp_json);
}

void construct_auth_start_req_payload(char** payload_ptr, const char* client_id)
{
    *payload_ptr = malloc(strlen(client_id) + 31);
    if (!*payload_ptr)
        return;
    if (sprintf(*payload_ptr, "client_id=%s&scope=email profile", client_id) < 0) {
        free(*payload_ptr);
        *payload_ptr = NULL;
    }
}

void construct_prompt(char** prompt_ptr, const char* verification_url, const char* user_code)
{
    *prompt_ptr = malloc(strlen(verification_url) + strlen(user_code) + 44);
    if (!*prompt_ptr)
        return;
    if (sprintf(*prompt_ptr, "Continue by visiting %s and using code %s there", verification_url, user_code) < 0) {
        free(*prompt_ptr);
        *prompt_ptr = NULL;
    }
}

void construct_poll_req_payload(
    char** payload_ptr, const char* client_id, const char* client_secret, const char* device_code)
{
    *payload_ptr = malloc(strlen(client_id) + strlen(client_secret) + strlen(device_code) + 82);
    if (!*payload_ptr)
        return;
    if (sprintf(*payload_ptr, "client_id=%s&client_secret=%s&code=%s&grant_type=http://oauth.net/grant_type/device/1.0",
            client_id, client_secret, device_code)
        < 0) {
        free(*payload_ptr);
        *payload_ptr = NULL;
    }
}

int authenticate_poll(const char* username, void (*prompt_callback)(const char*, void*), void* prompt_context,
    const char* openid_configuration_endpoint, const char* client_id, const char* client_secret)
{
    int retval = PAM_AUTH_ERR;
    CURLcode curlcode;

    client_id = client_id ? client_id : CLIENT_ID;
    client_secret = client_secret ? client_secret : CLIENT_SECRET;
    if (client_id == NULL || client_secret == NULL)
        goto end;

    char* device_auth_endpoint = NULL;
    char* token_endpoint = NULL;
    get_openid_configuration(openid_configuration_endpoint, &device_auth_endpoint, &token_endpoint);
    if (!device_auth_endpoint || !token_endpoint)
        goto end;

    char* auth_start_req_payload = NULL;
    construct_auth_start_req_payload(&auth_start_req_payload, client_id);
    if (!auth_start_req_payload)
        goto end;

    struct response auth_start_resp = { 0 };
    if ((curlcode = http_post(device_auth_endpoint, auth_start_req_payload, &auth_start_resp)) != CURLE_OK)
        goto end;
    cJSON* auth_start_resp_json = cJSON_Parse(auth_start_resp.body);
    if (!auth_start_resp_json)
        goto end;

    char* verification_url
        = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "verification_url"));
    char* user_code = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "user_code"));
    char* device_code = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "device_code"));
    int delay = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "interval"));
    int expiry = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(auth_start_resp_json, "expires_in"));
    if (!verification_url || !user_code || !device_code || delay == NAN || expiry == NAN)
        goto end;

    char* prompt = NULL;
    construct_prompt(&prompt, verification_url, user_code);
    if (!prompt)
        goto end;
    prompt_callback(prompt, prompt_context);

    char* poll_req_payload = NULL;
    construct_poll_req_payload(&poll_req_payload, client_id, client_secret, device_code);
    if (!poll_req_payload)
        goto end;

    char* token = NULL;
    int current_wait_time = 0;
    while (current_wait_time <= expiry) {
        struct response poll_resp = { 0 };
        if ((curlcode = http_post(token_endpoint, poll_req_payload, &poll_resp)) != CURLE_OK) {
            if (poll_resp.body)
                free(poll_resp.body);
            goto end;
        }

        fprintf(stderr, "poll response: %s\n", poll_resp.body);
        cJSON* poll_resp_json = cJSON_Parse(poll_resp.body);
        if (!poll_resp_json) {
            if (poll_resp.body)
                free(poll_resp.body);
            goto end;
        }

        if (cJSON_HasObjectItem(poll_resp_json, "error")) {
            char* error = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(poll_resp_json, "error"));
            fprintf(stderr, "Poll error: %s\n", error);
            if (!strcmp(error, "slow_down")) {
                delay++;
            }
        } else {
            token = strdup(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(poll_resp_json, "id_token")));
            fprintf(stderr, "Token: %s\n", token);
        }

        free(poll_resp.body);
        cJSON_Delete(poll_resp_json);

        if (token)
            break;

        sleep(delay);
    }
    if (token == NULL)
        goto end;

    retval = authenticate_id_token(username, token, openid_configuration_endpoint);

end:
    if (device_auth_endpoint)
        free(device_auth_endpoint);
    if (token_endpoint)
        free(token_endpoint);
    if (auth_start_req_payload)
        free(auth_start_req_payload);
    if (auth_start_resp.body)
        free(auth_start_resp.body);
    if (auth_start_resp_json)
        cJSON_Delete(auth_start_resp_json);
    if (prompt)
        free(prompt);
    if (poll_req_payload)
        free(poll_req_payload);
    if (token)
        free(token);
    return retval;
}