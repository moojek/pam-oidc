#ifndef AUTH_H
#define AUTH_H

int authenticateWithMotleyCue(const char* username, const char* token,
    const char* verificationEndpoint);
int authenticateWithIDToken(const char* username, const char* idToken, const char* openidConfigurationEndpoint);
int authenticateWithPolling(const char* username, void (*promptCallback)(const char*, void*), void* promptCallbackContext,
    const char* openidConfigurationEndpoint, const char* clientId, const char* clientSecret);

#endif // AUTH_H