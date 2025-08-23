CC = gcc
CXX = g++
LD = ld
CFLAGS = -std=c23 -fPIC -fno-stack-protector -c # -g -fsanitize=address
CFLAGS2 = -std=c23 -fPIC -fno-stack-protector # -g -fsanitize=address
LDFLAGS = -x --shared -lcurl -lcjson -ljwt
SRC = pam_lic.c http_client.c local_auth.c id_token_auth.c poll_auth.c pam_helper.c 
OBJ = pam_lic.o http_client.o local_auth.o id_token_auth.o poll_auth.o pam_helper.o
TARGET = /lib/security/pam_lic.so

TEST_SRC = test.c
TEST_BIN = pam_test
TEST_LIBS = -lpam -lpam_misc

.PHONY: all clean install test

all: $(OBJ)

$(OBJ): %.o : %.c
	$(CC) $(CFLAGS) -o $@ $<

install: all
	sudo $(LD) $(LDFLAGS) -o $(TARGET) $(OBJ)

scp: install
	scp $(TARGET) motley:/lib/x86_64-linux-gnu/security 

test: $(TEST_SRC) install
	$(CC) $(CFLAGS2) -o $(TEST_BIN) $(TEST_SRC) $(TEST_LIBS)

clean:
	rm -f $(OBJ) $(TEST_BIN)
