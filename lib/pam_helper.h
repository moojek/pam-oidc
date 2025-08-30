#ifndef PAM_HELPER_H
#define PAM_HELPER_H

#include <security/pam_modules.h>

int getUsername(pam_handle_t* pamh, const char** user);
int getInput(pam_handle_t* pamh, int flags, char** input, const char* prompt);
void displayText(pam_handle_t* pamh, const char* prompt);

#endif // PAM_HELPER_H