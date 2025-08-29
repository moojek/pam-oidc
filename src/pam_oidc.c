#include "auth.h"
#include "../lib/pam_helper.h"
#include <getopt.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) { return PAM_SUCCESS; }

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv) { return PAM_SUCCESS; }

void promptCallback(const char* prompt, void* context) { displayText((pam_handle_t*)context, prompt); }

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    int returnValue;

    const char* username;
    if (returnValue = getUsername(pamh, &username) != PAM_SUCCESS)
        return returnValue;

    fprintf(stderr, "%d args: '", argc);
    for (size_t i = 0; i < argc - 1; i++) {
        fprintf(stderr, "%s ", argv[i]);
    }
    if (argc > 0)
        fprintf(stderr, "%s'\n", argv[argc - 1]);

    char *clientID = NULL, *clientSecret = NULL, *verificationEndpoint = NULL, *openidConfigurationEndpoint = NULL;
    int c;

    while (1) {
        int optionIndex = 0;
        // clang-format off
        static struct option longOptions[] = {
            { "openid_config_url",  required_argument, 0, 4 },
            { "verify_endpoint",    required_argument, 0, 3 },
            { "client_id",          required_argument, 0, 1 },
            { "client_secret",      required_argument, 0, 2 },
            { 0, 0, 0, 0 }
        };
        // clang-format on

        c = getopt_long(argc + 1, (char* const*)(argv - 1), "", longOptions, &optionIndex);
        if (c == -1) {
            fprintf(stderr, "c==-1\n");
            break;
        }

        switch (c) {
        case 1:
            clientID = optarg;
            break;
        case 2:
            clientSecret = optarg;
            break;
        case 3:
            verificationEndpoint = optarg;
            break;
        case 4:
            openidConfigurationEndpoint = optarg;
            break;

        default:
            fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
            break;
        }
    }

    fprintf(stderr, "optind=%d, argc=%d\n", optind, argc);
    if (--optind >= argc) {
        fprintf(stderr, "No arguments specified - cannot determine mode of operation\n");
        return PAM_AUTH_ERR;
    }

    char* input;

    if (strcmp(argv[optind], "id_token") == 0) {
        getInput(pamh, flags, &input, "ID Token: ");
        return authenticateWithIDToken(username, input, openidConfigurationEndpoint);
    }
    if (strcmp(argv[optind], "local_auth") == 0) {
        getInput(pamh, flags, &input, "Access token: ");
        return authenticateWithMotleyCue(username, input, verificationEndpoint);
    }
    if (strcmp(argv[optind], "poll") == 0) {
        return authenticateWithPolling(
            username, &promptCallback, pamh, openidConfigurationEndpoint, clientID, clientSecret);
    }

    fprintf(stderr, "\nInvalid mode of operation %s\n", argv[optind]);
    return PAM_AUTH_ERR;
}