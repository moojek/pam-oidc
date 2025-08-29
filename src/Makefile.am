pam_LTLIBRARIES = pam_oidc.la
pamdir = $(libdir)/security
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/lib
AM_CFLAGS = -std=c2x -fPIC -fno-stack-protector
pam_oidc_la_SOURCES = pam_oidc.c local_auth.c id_token_auth.c poll_auth.c
pam_oidc_la_LDFLAGS = -module -avoid-version -shared
pam_oidc_la_LIBADD = -lpam -lpam_misc -lcurl -lcjson -ljwt -lc ../lib/libhelpers.la

noinst_HEADERS = auth.h
