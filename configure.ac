
AC_INIT([pam_oidc],[0.1.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/pam_oidc.c])
AC_CONFIG_MACRO_DIRS([m4])


# Checks for programs.
AC_PROG_CC
AM_PROG_AR
LT_INIT

# Checks for libraries.
AC_CHECK_LIB([pam], [pam_start])
# AC_CHECK_LIB([pam_misc], [misc_conv])
AC_CHECK_LIB([curl], [curl_easy_init])
AC_CHECK_LIB([cjson], [cJSON_Parse])
AC_CHECK_LIB([jwt], [jwt_new])

# Checks for header files.
AC_CHECK_HEADERS([security/pam_appl.h security/pam_misc.h curl/curl.h cjson/cJSON.h jwt.h])

AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile lib/Makefile])
AC_OUTPUT
