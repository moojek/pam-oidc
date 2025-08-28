#ifndef AUTH_H
#define AUTH_H

int authenticate_local(const char* username, const char* token,
    const char* verify_endpoint);
int authenticate_id_token(const char* username, const char* id_token);
int authenticate_poll(const char* username, void (*prompt_callback)(const char*, void*), void* prompt_context,
    const char* client_id, const char* client_secret);

#endif // AUTH_H