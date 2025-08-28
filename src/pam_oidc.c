#include "auth.h"
#include "pam_helper.h"
#include <getopt.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    printf("Acct mgmt\n");
    return PAM_SUCCESS;
}

void prompt_callback(const char* prompt, void* context)
{
    // fprintf(stderr, "start prompt callback\n\n");
    display_text((pam_handle_t*)context, prompt);
    // fprintf(stderr, "end prompt callback\n\n");
}

// enum operation_mode {
//     id_token = 1,
//     local_auth = 2,
//     poll = 4
// };

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    const char* username;
    get_username(pamh, &username, "Username: ");
    // printf("Welcome %s\n", username);

    fprintf(stderr, "%d args: '", argc);
    for (size_t i = 0; i < argc - 1; i++) {
        fprintf(stderr, "%s ", argv[i]);
    }
    if (argc > 0)
        fprintf(stderr, "%s'\n", argv[argc - 1]);

    char *client_id = NULL, *client_secret = NULL;
    int c;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "client_id", required_argument, 0, 1 },
            { "client_secret", required_argument, 0, 2 },
            { 0, 0, 0, 0 }
        };

        c = getopt_long(argc + 1, (char* const*)(argv - 1), "", long_options, &option_index);
        if (c == -1) {
            fprintf(stderr, "c==-1\n");
            break;
        }

        switch (c) {
        case 1:
            client_id = optarg;
            break;
        case 2:
            client_secret = optarg;
            break;

        default:
            fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
            break;
        }
    }

    if (--optind + 1 < argc) {
        fprintf(stderr, "No arguments specified - cannot determine mode of operation\n");
        return PAM_AUTH_ERR;
    }

    char* input;

    if (strcmp(argv[optind], "id_token") == 0) {
        get_input(pamh, flags, &input, "ID Token: ");
        return authenticate_id_token(username, input);
    }
    if (strcmp(argv[optind], "local_auth") == 0) {
        get_input(pamh, flags, &input, "Access token: ");
        return authenticate_local(username, input);
    }
    if (strcmp(argv[optind], "poll") == 0) {
        return authenticate_poll(username, &prompt_callback, pamh, client_id, client_secret);
    }

    fprintf(stderr, "\nInvalid mode of operation %s\n", argv[optind]);
    return PAM_AUTH_ERR;
}