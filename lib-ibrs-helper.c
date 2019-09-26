#include "lib-ibrs-helper.h"

int socket_id = 0;

int authenticate(char* username, char* groupname, char* ids_buffer){
    FILE* list_file;
    char* file_buffer;
    char* token;
    struct stat st = {0};

    if(strncmp(ids_buffer, "NULL", 4) == 0){

        if (stat(groupname, &st) == -1)
            return 0;
        
        long file_size;
        char directory[50];
        sprintf(directory, "./%s/ids.txt", groupname);

        // LETTURA DEL FILE "ids.txt"
        list_file = fopen(directory, "r");
        file_size = get_filesize(list_file);
        file_buffer = calloc(file_size, sizeof(char));
        if(fread(file_buffer, sizeof(char), file_size, list_file) != file_size){
            printf("problema nella read del file %s\n", directory);
            exit(EXIT_FAILURE);
        }
    }
    else{
        file_buffer = calloc(strlen(ids_buffer), sizeof(char));
        sprintf(file_buffer, "%s", ids_buffer);
    }

    token = strtok(file_buffer, "\n");
    while(token != NULL){
        if(strncmp(username, token, strlen(username)) == 0){
            printf("Autenticazione eseguita con successo\n");
            return 1;
        }
        token = strtok(NULL, "\n");
    }
    return 0;
}

void ibrs_startup(char* groupname, char* username) {
    srand(time(NULL));

    gmp_randstate_t prng;
    ibrs_public_params_t public_params;
    ibrs_secret_param_t secret_param;

    FILE* param_stream, *pairing_stream, *keys_stream, *secret_stream;
    char* directory;
    
    directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/param.txt", groupname);
    param_stream = fopen(directory, "w");
    free(directory);

    directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/pairing.txt", groupname);
    pairing_stream = fopen(directory, "w");
    free(directory);

    directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/secret.txt", groupname);
    secret_stream = fopen(directory, "w");
    free(directory);

    keys_stream = fopen("keys.txt", "w");
    
    // Calibrating tools for timing
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();

    // Inizializing PRNG
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, prng_sec_level);

    // Generating params
    generate_params(&public_params, &secret_param, default_sec_level, pairing_stream, param_stream, secret_stream);
    
    fclose(pairing_stream);
    fclose(param_stream);
    fclose(secret_stream);

    // Generating keys
    ibrs_key_pair keys;
    
    ibrs_keys_gen(&public_params, &secret_param, &keys, username, keys_stream);
    fclose(keys_stream);
    ibrs_keys_clear(&keys);
    
    ibrs_params_clear(&public_params, &secret_param);
    gmp_randclear(prng);
}

void generate_keys(char* groupname, char* username){
    srand(time(NULL));

    gmp_randstate_t prng;
    ibrs_public_params_t public_params;
    ibrs_secret_param_t secret_param;

    FILE* param_stream, *pairing_stream, *keys_stream, *secret_stream;
    char* directory;
    
    directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/param.txt", groupname);
    param_stream = fopen(directory, "r");
    free(directory);

    directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/pairing.txt", groupname);
    pairing_stream = fopen(directory, "r");
    free(directory);

    directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/secret.txt", groupname);
    secret_stream = fopen(directory, "r");
    free(directory);

    keys_stream = fopen("keys.txt", "w");

    // Calibrating tools for timing
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();

    // Inizializing PRNG
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, prng_sec_level);

    // Loading params
    load_params_with_secret(&public_params, &secret_param, default_sec_level, pairing_stream, param_stream, secret_stream);

    // Keygen
    ibrs_key_pair keys;

    ibrs_keys_gen(&public_params, &secret_param, &keys, username, keys_stream);
    fclose(keys_stream);
    ibrs_keys_clear(&keys);
    
    ibrs_params_clear(&public_params, &secret_param);
    gmp_randclear(prng);
}

void send_params(int socket_fd, char* groupname){
    FILE* stream;
    char* buffer;
    char* directory;
    long size;

    // INVIO DATI PAIRING
    directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/pairing.txt", groupname);
    stream = fopen(directory, "r");
    size = get_filesize(stream);
    buffer = calloc(1024, sizeof(char));
    if(fread(buffer, sizeof(char),size, stream) != size) {
        printf("problema nella read di stream\n");
        exit(EXIT_FAILURE);
    }

    if(write(socket_fd, buffer, 1024) == -1) {
        printf("Problemi nella write sulla socket\n");
        return;
    }
    free(buffer);
    free(directory);
    fclose(stream);

    // INVIO PARAMETRI
    directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/param.txt", groupname);
    stream = fopen(directory, "r");
    size = get_filesize(stream);
    buffer = calloc(1024, sizeof(char));
    if(fread(buffer, sizeof(char), size, stream) != size) {
        printf("problema nella read di stream\n");
        exit(EXIT_FAILURE);
    }

    if(write(socket_fd, buffer, 1024) == -1) {
        printf("Problemi nella write sulla socket\n");
        return;
    }
    free(buffer);
    free(directory);
    fclose(stream);

    // INVIO CHIAVI
    stream = fopen("keys.txt", "r");
    size = get_filesize(stream);
    buffer = calloc(1024, sizeof(char));
    if(fread(buffer, sizeof(char), size, stream) != size) {
        printf("problema nella read di stream\n");
        exit(EXIT_FAILURE);
    }

    if(write(socket_fd, buffer, 1024) == -1) {
        printf("Problemi nella write sulla socket\n");
        return;
    }
}

int connect_socket(char serv_addr[], int port){

    int socket_fd; 
    struct sockaddr_in servaddr; 
  
    // socket create and varification 
    socket_fd = socket(AF_INET, SOCK_STREAM, 0); 
    if (socket_fd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(&servaddr, sizeof(servaddr));
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr(serv_addr); 
    servaddr.sin_port = htons(port);

    if (connect(socket_fd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
        printf("connection with the server failed...\n"); 
        exit(0);
    } 
    else
        printf("connected to the server..\n");

    socket_id = socket_fd;
    return socket_fd;
}

void start_exchange(int socket_fd){
    char* buffer;
    char* ids_buffer;
    char* username;
    char* groupname;
    char* directory;
    char* token;
    
    struct stat st = {0};
    int auth;
    int socket_cs;
    int send_cs = 0;

    // RICEZIONE USERNAME E GROUPNAME
    buffer = calloc(50, sizeof(char));
    if(read(socket_fd, buffer, 50) == -1) {
        printf("Problemi nella read dalla socket\n");
        return;
    }
    
    if(strlen(buffer) <=0 ){
        printf("Input invalido.\n");
        if(write(socket_fd, "NULL", 4) == -1) {
            printf("Problemi nella write sulla socket\n");
            return;
        } 
        return;      
    }

    token = strtok(buffer, ",");
    username = calloc(50, sizeof(char));
    groupname = calloc(50, sizeof(char));
    
    strncpy(username, token, strlen(token));
    token = strtok(NULL, ",");
    strncpy(groupname, token, strlen(token));

    if(write(socket_fd, "ACK", 3) == -1) {
        printf("Problemi nella write sulla socket\n");
        return;
    }

    printf("USERNAME & GROUPNAME: %s & %s\n", username, groupname);

    // RICEZIONE LISTA UTENTI DEL GRUPPO
    ids_buffer = calloc(1024, sizeof(char));
    if(read(socket_fd, ids_buffer, 1024) == -1) {
        printf("Problemi nella read dalla socket\n");
        return;
    }
    
    // AUTENTICAZIONE DELL'UTENTE
    auth = authenticate(username, groupname, ids_buffer);
    if(auth == 0){
        if(write(socket_fd, "FAIL_AUTH", 9) == -1) {
            printf("Problemi nella write sulla socket\n");
            return;
        }
        printf("Autenticazione fallita\n");
        free(buffer);
        free(username);
        free(groupname);
        return;
    }

    if(strcmp(ids_buffer, "") == 0){
        if(write(socket_fd, "EMPTY", 5) == -1){
            printf("Problemi nella write sulla socket\n");
            return;
        }
        printf("File IDS vuoto\n");
    }

    if(strncmp(ids_buffer, "NULL", 4) != 0){

        // CREAZIONE DIRECTORY GROUPNAME - CONTROLLO SE LA DIRECTORY ESISTE GIA'
        if (stat(groupname, &st) == -1) {
            mkdir(groupname, 0700);

            // CREAZIONE FILE IDS.TXT DENTRO LA CARTELLA GROUPNAME
            directory = calloc(100, sizeof(char));
            sprintf(directory, "./%s/ids.txt", groupname);

            FILE *file_to_open;
            file_to_open = fopen(directory, "w");
            fprintf(file_to_open, "%s", ids_buffer);
            fclose(file_to_open);

            // CREAZIONE FILE PARAM.TXT E PAIRING.TXT
            ibrs_startup(groupname, username);

            // INVIO IDS_BUFFER A CS
            char ack[5];

            socket_cs = connect_socket("127.0.0.1", 8888);
            if(write(socket_cs, "group_admin ", 12) == -1) {
                printf("Problemi nella write sulla socket\n");
                return;
            }
            while(strncmp(ack, "ACK", 3) != 0) {
                if(read(socket_cs, ack, 3) == -1) {
                    printf("Problemi nella read dalla socket\n");
                    return;
                } 
            }

            if(write(socket_cs, groupname, strlen(groupname)) == -1) {
                printf("Problemi nella write sulla socket\n");
                return;
            }
            sprintf(ack, "%s", "");
            while(strncmp(ack, "ACK", 3) != 0) {
                if(read(socket_cs, ack, 3) == -1) {
                    printf("Problemi nella read dalla socket\n");
                    return;
                }
            }
            
            if(write(socket_cs, ids_buffer, strlen(ids_buffer)) == -1) {
                printf("Problemi nella write sulla socket\n");
                return;
            }
            send_cs = 1;
            free(directory);
        }
        // IL GRUPPO RICHIESTO E' GIA' PRESENTE
        else{
            if(write(socket_fd, "EXIST", 5) == -1) {
                printf("Problemi nella write sulla socket\n");
                return;
            }

            printf("Gruppo già esistente\n");
            free(buffer);
            free(username);
            free(groupname);
            return;
        }
    }
    else{
        generate_keys(groupname, username);
    }
    
    // INVIO PARAMETRI A GM E CS
    if (stat(groupname, &st) == 0){

        send_params(socket_fd, groupname);
        if (send_cs == 1) {
            send_params(socket_cs, groupname);
        }
    }
    else{
        if(write(socket_fd, "NULL", 4) == -1) {
            printf("Problemi nella read dalla socket\n");
            return;
        }
        printf("Gruppo Inesistente\n");
    }

    //ELIMINA FILE KEYS.TXT
    if(remove("keys.txt") != 0){
        printf("Impossibile rimuovere il file keys.txt");
        return;
    }

    free(buffer);
    free(username);
    free(groupname);
    free(ids_buffer);
}

void start_connection(){
	
	int socket_fd, connfd, len; 
    struct sockaddr_in servaddr, cli; 
  
    // socket create and verification 
    socket_fd = socket(AF_INET, SOCK_STREAM, 0); 
    if (socket_fd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else {
        printf("Socket successfully created..\n"); 
    }
    bzero(&servaddr, sizeof(servaddr)); 
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 
  
    // Binding newly created socket to given IP and verification 
    if ((bind(socket_fd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        exit(0); 
    }
    else {
        printf("Socket successfully binded..\n"); 
    }
    
  	while(1){
	    // Now server is ready to listen and verification 
	    if ((listen(socket_fd, 5)) != 0) { 
	        printf("Listen failed...\n"); 
	        exit(0); 
	    } 
	    else
	        printf("Server listening..\n"); 
	    len = sizeof(cli);
	  
	    // Accept the data packet from client and verification 
	    connfd = accept(socket_fd, (SA*)&cli, (socklen_t*)&len); 
	    if (connfd < 0) { 
	        printf("server acccept failed...\n"); 
	        exit(0); 
	    } 
	    else
	        printf("server acccept the client...\n"); 
	  
	    // Function for chatting between client and server 
	    start_exchange(connfd);
	}
    close(socket_fd);
}