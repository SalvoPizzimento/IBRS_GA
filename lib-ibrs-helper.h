#ifndef LIB_IBRS_HELPER_H
#define LIB_IBRS_HELPER_H
#define _GNU_SOURCE

#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h>
#include <gmp.h>
#include <libgen.h>
#include <stdbool.h>
#include <assert.h>
#include <pbc/pbc.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "lib-ibrs-params.h"
#include "lib-ibrs-keys.h"

#define PORT 8080 
#define SA struct sockaddr 
#define prng_sec_level 96
#define default_sec_level 80
#define psw_cs "root"

long get_filesize(FILE *fp);
int authenticate(char* username, char* groupname, char* ids_buffer);
void ibrs_startup(char* groupname, char* username);
void send_params(int socket_fd, char* groupname);

int connect_socket(char serv_addr[], int port);
void start_exchange(int socket_id);
void start_connection();

#endif /* LIB_IBRS_HELPER_H */