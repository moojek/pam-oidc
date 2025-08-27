#include "auth.h"
#include "pam_helper.h"
#include <getopt.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>

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

enum operation_mode {
    id_token = 1,
    local_auth = 2,
    poll = 4
};

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    fprintf(stderr, "%d args: '", argc);
    for (size_t i = 0; i < argc - 1; i++) {
        fprintf(stderr, "%s ", argv[i]);
    }
    if (argc > 0)
        fprintf(stderr, "%s'\n", argv[argc - 1]);

    int c;

    unsigned int mode_of_operation = 0;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "id-token", no_argument, 0, 'i' },
            { "local-auth", no_argument, 0, 'l' },
            { "poll", no_argument, 0, 'p' },
            { 0, 0, 0, 0 }
        };

        c = getopt_long(argc + 1, (char* const*)--argv, "ilp", long_options, &option_index);
        if (c == -1) {
            fprintf(stderr, "c==-1\n");
            break;
        }

        switch (c) {
        case 'i':
            fprintf(stderr, "option i\n");
            mode_of_operation |= id_token;
            break;

        case 'l':
            fprintf(stderr, "option l\n");
            mode_of_operation |= local_auth;
            break;

        case 'p':
            fprintf(stderr, "option p\n");
            mode_of_operation |= poll;
            break;

        default:
            fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
            break;
        }
    }

    const char* pUsername;
    get_username(pamh, &pUsername, "Username: ");
    printf("Welcome %s\n", pUsername);

    char* input;

    switch (mode_of_operation) {
    case local_auth:
        get_input(pamh, flags, &input, "Access token: ");
        return authenticate_local(pUsername, input);
        break;

    case id_token:
        get_input(pamh, flags, &input, "ID Token: ");
        return authenticate_id_token(pUsername, input);

    case poll:
        return authenticate_poll(pUsername, &prompt_callback, pamh);

    default:
        fprintf(stderr, "Invalid mode of operation %d\n", mode_of_operation);
        return PAM_AUTH_ERR;
        break;
    }

    return authenticate_local(pUsername, input);

    // char* userinfo_endpoint;
    // struct response well_known_resp = { 0 };
    // CURLcode code = http_get("https://accounts.google.com/.well-known/openid-configuration", &well_known_resp);
    // // fprintf(stderr, ".well-known GET CURLcode is %d\n", code);
    // if (code != 0)
    //     return PAM_AUTH_ERR;
    // // fprintf(stderr, "body is %s\n", well_known_resp.body);

    // // fprintf(stderr, "begin parse\n");
    // cJSON* json = cJSON_Parse(well_known_resp.body);
    // // fprintf(stderr, "end parse\n");
    // // fprintf(stderr, "json is %d\n", json);
    // // fprintf(stderr, "valuestring is %s\n", json->valuestring);
    // // fprintf(stderr, "begin getobj\n");
    // cJSON* userinfo_endpoint_json = cJSON_GetObjectItemCaseSensitive(json, "userinfo_endpoint");
    // // fprintf(stderr, "end getobj\n");
    // // fprintf(stderr, "begin malloc\n");
    // // fprintf(stderr, "json is %d\n", userinfo_endpoint_json);
    // // fprintf(stderr, "valuestring is %s\n", userinfo_endpoint_json->valuestring);
    // // fprintf(stderr, "__size is %d\n", strlen(userinfo_endpoint_json->valuestring) + 1);
    // userinfo_endpoint = malloc(strlen(userinfo_endpoint_json->valuestring) + 1);
    // // fprintf(stderr, "end malloc\n");
    // // fprintf(stderr, "begin strcpy\n");
    // strcpy(userinfo_endpoint, userinfo_endpoint_json->valuestring);
    // // fprintf(stderr, "end strcpy\n");
    // printf("userinfo = %s\n", userinfo_endpoint);

    // cJSON_Delete(json);
    // free(well_known_resp.body);
    // // fprintf(stderr, "Userinfo endpoint is %s\n", userinfo_endpoint);

    // char* input;
    // struct pam_message msg[1], *pmsg[1];
    // struct pam_response* resp;
    // pmsg[0] = &msg[0];
    // msg[0].msg_style = PAM_PROMPT_ECHO_ON;
    // msg[0].msg = "Token: ";
    // resp = NULL;
    // if ((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS)
    //     return retval;

    // if (resp) {
    //     if (flags & PAM_DISALLOW_NULL_AUTHTOK && resp[0].resp == NULL) {
    //         free(resp);
    //         return PAM_AUTH_ERR;
    //     }
    //     input = resp[0].resp;
    //     resp[0].resp = NULL;
    // } else
    //     return PAM_CONV_ERR;

    // struct response userinfo_resp = { 0 };
    // fprintf(stderr, "token is %s\n", input);
    // code = http_get_with_bearer_token(userinfo_endpoint, input, &userinfo_resp);
    // // fprintf(stderr, ".well-known GET CURLcode is %d\n", code);
    // if (code != 0)
    //     return PAM_AUTH_ERR;
    // fprintf(stderr, "body is %s\n", userinfo_resp.body);

    // json = cJSON_Parse(userinfo_resp.body);
    // if (json == NULL)
    //     return PAM_AUTH_ERR;

    // // fprintf(stderr, "JSON parse through\n");
    // cJSON_Delete(json);
    // // fprintf(stderr, "JSON delete through\n");
    // free(userinfo_resp.body);
    // // fprintf(stderr, "free through\n");

    // return PAM_SUCCESS;
}