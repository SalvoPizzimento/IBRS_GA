/** @file lib-ibrs-helper.h
 *  @brief Prototipi delle funzioni per l'helper del Group Admin.
 *
 *  Contiene i prototipi per l'helper,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */

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

int socket_id;

/** @brief Funzione per autenticare un'identità ad un gruppo.
 *  @param username identità da autenticare
 *  @param groupname gruppo su cui autenticare l'identità
 *  @param ids_buffer lista delle indentità in cui cercare
 *  @return 1 se l'autenticazione è avvenuta con successo, 0 altrimenti
 */
int authenticate(char* username, char* groupname, char* ids_buffer);

/** @brief Funzione per creare un ambiente IBRS.
 *  @param username identità per cui creare la coppia di chiavi
 *  @param groupname gruppo di appartenenza dell'identità
 */
void ibrs_startup(char* username, char* groupname);

/** @brief Funzione per mandare i parametri attraverso una socket.
 *  @param socket_fd socket attraverso cui mandare i parametri
 *  @param groupname gruppo per cui i parametri saranno validi
 */
void send_params(int socket_fd, char* groupname);

/** @brief Funzione per connettersi ad una socket tramite IP e PORTA.
 *  @param serv_addr[] indirizzo IP a cui connettersi
 *  @param port porta a cui connettersi
 *  @return descrittore della socket connessione socket creata
 */
int connect_socket(char serv_addr[], int port);

/** @brief Funzione principale per cominciare uno scambio di dati tramite socket.
 *  @param socket_id socket con cui cominciare lo scambio
 */
void start_exchange(int socket_id);

/** @brief Funzione per iniziare la connessione tramite socket.
 */
void start_connection();

#endif /* LIB_IBRS_HELPER_H */