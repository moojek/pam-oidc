#include "pam_helper.h"

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int getUsername(pam_handle_t* pamh, const char** user)
{
    return pam_get_user(pamh, user, NULL);
}

int converse(pam_handle_t* pamh, int nargs, struct pam_message** message, struct pam_response** response)
{
    fprintf(stderr, "start converse\n");
    int retval;
    struct pam_conv* conv;

    retval = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    fprintf(stderr, "PAM_CONV acquired with status %d\n", retval);
    if (!conv || !conv->conv) {
        fprintf(stderr, "Conversation function is NULL\n");
        return PAM_SYSTEM_ERR;
    }
    fprintf(stderr, "conv=%p conv->conv=%p appdata_ptr=%p message=%p response=%p\n",
        (void*)conv, (void*)conv->conv, conv->appdata_ptr, (void*)message, (void*)response);
    if (retval == PAM_SUCCESS) {
        retval = conv->conv(nargs, (const struct pam_message**)message, response, conv->appdata_ptr);
    }

    return retval;
}

int getInput(pam_handle_t* pamh, int flags, char** input, const char* prompt)
{
    int retval;
    struct pam_message msg[1], *pmsg[1];
    struct pam_response* resp;
    pmsg[0] = &msg[0];
    msg[0].msg_style = PAM_PROMPT_ECHO_ON;
    msg[0].msg = prompt;
    resp = NULL;
    if ((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS)
        return retval;

    if (resp) {
        if (flags & PAM_DISALLOW_NULL_AUTHTOK && resp[0].resp == NULL) {
            free(resp);
            return PAM_AUTH_ERR;
        }
        *input = resp[0].resp;
        resp[0].resp = NULL;
    } else
        return PAM_CONV_ERR;
}

void displayText(pam_handle_t* pamh, const char* prompt)
{
    int retval;
    struct pam_message msg[1], *pmsg[1];
    struct pam_response* resp;
    pmsg[0] = &msg[0];
    msg[0].msg_style = PAM_TEXT_INFO;
    msg[0].msg = prompt;
    resp = NULL;
    converse(pamh, 1, pmsg, &resp);
}
