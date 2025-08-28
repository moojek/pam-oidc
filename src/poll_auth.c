#include "auth.h"
#include "http_client.h"

#include <cjson/cJSON.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CLIENT_ID
#define CLIENT_ID NULL
#endif
#ifndef CLIENT_SECRET
#define CLIENT_SECRET NULL
#endif

int authenticate_poll(const char* username, void (*prompt_callback)(const char*, void*), void* prompt_context,
    const char* client_id, const char* client_secret)
{
    client_id = client_id ? client_id : CLIENT_ID;
    client_secret = client_secret ? client_secret : CLIENT_SECRET;
    if (client_id == NULL || client_secret == NULL)
        return PAM_AUTH_ERR;
    // fprintf(stderr, "client_id=%s\nclient_secret=%s\n", client_id, client_secret);

    char* payload = malloc(strlen(client_id) + 31);
    sprintf(payload, "client_id=%s&scope=email profile", client_id);
    struct response response = { 0 };
    http_post("https://oauth2.googleapis.com/device/code", payload, &response);
    free(payload);

    // fprintf(stderr, "response: %s\n\n", response.body);
    cJSON* json = cJSON_Parse(response.body);
    char* verification_url = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "verification_url"));
    char* user_code = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "user_code"));
    char* prompt = malloc(strlen(verification_url) + strlen(user_code) + 44);
    sprintf(prompt, "Continue by visiting %s and using code %s there", verification_url, user_code);
    // fprintf(stderr, "verification url: %s\nuser code: %s\nprompt: %s\n\n", verification_url, user_code, prompt);
    prompt_callback(prompt, prompt_context);
    // free(prompt);

    char* device_code = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "device_code"));
    payload = malloc(strlen(client_id) + strlen(client_secret) + strlen(device_code) + 82);
    sprintf(payload, "client_id=%s&client_secret=%s&code=%s&grant_type=http://oauth.net/grant_type/device/1.0", client_id, client_secret, device_code);
    int delay = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json, "interval"));
    int expiry = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json, "expires_in"));
    cJSON_Delete(json);
    int current_wait_time = 0;
    char* token = NULL;
    while (current_wait_time <= expiry) {
        struct response response = { 0 };
        http_post("https://oauth2.googleapis.com/token", payload, &response);

        fprintf(stderr, "poll response: %s\n", response.body);
        json = cJSON_Parse(response.body);
        if (cJSON_HasObjectItem(json, "error")) {
            char* error = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "error"));
            fprintf(stderr, "Poll error: %s\n", error);
            if (!strcmp(error, "slow_down")) {
                delay++;
            }
            free(error);
        } else {
            token = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "id_token"));
            fprintf(stderr, "Token: %s\n", token);
            break;
        }
        sleep(delay);
    }
    if (token == NULL)
        return PAM_AUTH_ERR;

    int ret = authenticate_id_token(username, token);
    free(token);
    return ret;
}