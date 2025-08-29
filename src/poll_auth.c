#include "auth.h"
#include "../lib/http_client.h"

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

void getOpenIDConfiguration(const char* openidConfigurationEndpoint, char** deviceAuthenticationEndpointStringPointer,
    char** tokenEndpointStringPointer)
{
    *deviceAuthenticationEndpointStringPointer = NULL;
    *tokenEndpointStringPointer = NULL;

    cJSON* openidConfigurationResponseJSON = getAsJSON(openidConfigurationEndpoint);
    if (!openidConfigurationResponseJSON)
        goto end;

    char* deviceAuthenticationEndpoint = cJSON_GetStringValue(
        cJSON_GetObjectItemCaseSensitive(openidConfigurationResponseJSON, "device_authorization_endpoint"));
    if (!deviceAuthenticationEndpoint)
        goto end;
    *deviceAuthenticationEndpointStringPointer = strdup(deviceAuthenticationEndpoint);

    char* tokenEndpoint
        = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(openidConfigurationResponseJSON, "token_endpoint"));
    if (!tokenEndpoint)
        goto end;
    *tokenEndpointStringPointer = strdup(tokenEndpoint);

end:
    if (openidConfigurationResponseJSON)
        cJSON_Delete(openidConfigurationResponseJSON);
}

void constructAuthenticationStartRequestPayload(char** payloadStringPointer, const char* clientId)
{
    *payloadStringPointer = malloc(strlen(clientId) + 31);
    if (!*payloadStringPointer)
        return;
    if (sprintf(*payloadStringPointer, "client_id=%s&scope=email profile", clientId) < 0) {
        free(*payloadStringPointer);
        *payloadStringPointer = NULL;
    }
}

void constructPrompt(char** promptStringPointer, const char* verificationURL, const char* userCode)
{
    *promptStringPointer = malloc(strlen(verificationURL) + strlen(userCode) + 44);
    if (!*promptStringPointer)
        return;
    if (sprintf(*promptStringPointer, "Continue by visiting %s and using code %s there", verificationURL, userCode)
        < 0) {
        free(*promptStringPointer);
        *promptStringPointer = NULL;
    }
}

void constructPollRequestPayload(
    char** payloadStringPointer, const char* clientID, const char* clientSecret, const char* deviceCode)
{
    *payloadStringPointer = malloc(strlen(clientID) + strlen(clientSecret) + strlen(deviceCode) + 82);
    if (!*payloadStringPointer)
        return;
    if (sprintf(*payloadStringPointer,
            "client_id=%s&client_secret=%s&code=%s&grant_type=http://oauth.net/grant_type/device/1.0", clientID,
            clientSecret, deviceCode)
        < 0) {
        free(*payloadStringPointer);
        *payloadStringPointer = NULL;
    }
}

int authenticateWithPolling(const char* username, void (*promptCallback)(const char*, void*),
    void* promptCallbackContext, const char* openidConfigurationEndpoint, const char* clientID,
    const char* clientSecret)
{
    int retval = PAM_AUTH_ERR;
    char* deviceAuthenticationEndpoint = NULL;
    char* tokenEndpoint = NULL;
    char* authenticationStartRequestPayload = NULL;
    cJSON* authenticationStartResponseJSON = NULL;
    char* prompt = NULL;
    char* pollRequestPayload = NULL;
    char* token = NULL;
    int currentWaitTimeValue;

    clientID = clientID ? clientID : CLIENT_ID;
    clientSecret = clientSecret ? clientSecret : CLIENT_SECRET;
    if (openidConfigurationEndpoint == NULL)
        openidConfigurationEndpoint = OPENID_CONFIGURATION_ENDPOINT;
    if (clientID == NULL || clientSecret == NULL)
        goto end;

    getOpenIDConfiguration(openidConfigurationEndpoint, &deviceAuthenticationEndpoint, &tokenEndpoint);
    if (!deviceAuthenticationEndpoint || !tokenEndpoint)
        goto end;

    constructAuthenticationStartRequestPayload(&authenticationStartRequestPayload, clientID);
    if (!authenticationStartRequestPayload)
        goto end;

    authenticationStartResponseJSON = postAsJSON(deviceAuthenticationEndpoint, authenticationStartRequestPayload);
    if (!authenticationStartResponseJSON)
        goto end;

    char* verificationUrl
        = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(authenticationStartResponseJSON, "verification_url"));
    char* userCode
        = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(authenticationStartResponseJSON, "user_code"));
    char* deviceCode
        = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(authenticationStartResponseJSON, "device_code"));
    int delay = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(authenticationStartResponseJSON, "interval"));
    int expiry = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(authenticationStartResponseJSON, "expires_in"));
    if (!verificationUrl || !userCode || !deviceCode || delay == NAN || expiry == NAN)
        goto end;

    constructPrompt(&prompt, verificationUrl, userCode);
    if (!prompt)
        goto end;
    promptCallback(prompt, promptCallbackContext);

    constructPollRequestPayload(&pollRequestPayload, clientID, clientSecret, deviceCode);
    if (!pollRequestPayload)
        goto end;

    currentWaitTimeValue = 0;
    while (currentWaitTimeValue <= expiry) {
        cJSON* pollResponseJSON = postAsJSON(tokenEndpoint, pollRequestPayload);
        if (!pollResponseJSON)
            goto end;

        if (cJSON_HasObjectItem(pollResponseJSON, "error")) {
            char* error = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(pollResponseJSON, "error"));
            fprintf(stderr, "Poll error: %s\n", error);
            if (!strcmp(error, "slow_down")) {
                delay++;
            }
        } else {
            token = strdup(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(pollResponseJSON, "id_token")));
            fprintf(stderr, "Token: %s\n", token);
        }

        cJSON_Delete(pollResponseJSON);
        if (token)
            break;

        sleep(delay);
    }
    if (token == NULL)
        goto end;

    retval = authenticateWithIDToken(username, token, openidConfigurationEndpoint);

end:
    if (deviceAuthenticationEndpoint)
        free(deviceAuthenticationEndpoint);
    if (tokenEndpoint)
        free(tokenEndpoint);
    if (authenticationStartRequestPayload)
        free(authenticationStartRequestPayload);
    if (authenticationStartResponseJSON)
        cJSON_Delete(authenticationStartResponseJSON);
    if (prompt)
        free(prompt);
    if (pollRequestPayload)
        free(pollRequestPayload);
    if (token)
        free(token);
    return retval;
}