#include "auth.h"
#include "http_client.h"

#include <cjson/cJSON.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char* CLIENT_ID = "683392123229-sj57mvnsjpor7au4p7iq9pvq74ipvt1t.apps.googleusercontent.com";
const char* CLIENT_SECRET = "***";

int authenticate_poll(const char* username, void (*prompt_callback)(const char*, void*), void* prompt_context)
{
    // fprintf(stderr, )
    char* payload = malloc(strlen(CLIENT_ID) + 31);
    sprintf(payload, "client_id=%s&scope=email profile", CLIENT_ID);
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
    payload = malloc(strlen(CLIENT_ID) + strlen(CLIENT_SECRET) + strlen(device_code) + 82);
    sprintf(payload, "client_id=%s&client_secret=%s&code=%s&grant_type=http://oauth.net/grant_type/device/1.0", CLIENT_ID, CLIENT_SECRET, device_code);
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