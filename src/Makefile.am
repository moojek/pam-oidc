pam_LTLIBRARIES = pam_lic.la
pamdir = $(libdir)/security
AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = -std=c23 -fPIC -fno-stack-protector
pam_lic_la_SOURCES = pam_lic.c http_client.c local_auth.c id_token_auth.c poll_auth.c pam_helper.c jwt_helper.c
pam_lic_la_LDFLAGS = -module -avoid-version -shared
pam_lic_la_LIBADD = -lpam -lpam_misc -lcurl -lcjson -ljwt

noinst_HEADERS = auth.h http_client.h jwt_helper.h pam_helper.h
