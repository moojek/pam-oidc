#ifndef PAM_HELPER_H
#define PAM_HELPER_H

#include <security/pam_appl.h>

void get_username(pam_handle_t* pamh, const char** user, const char* prompt);
int get_input(pam_handle_t* pamh, int flags, char** input, const char* prompt);
void display_text(pam_handle_t* pamh, const char* prompt);

#endif // PAM_HELPER_H