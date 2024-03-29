/** @file lib-ibrs-params.c
 *  @brief Parametri per il Group Admin.
 *
 *  File contenente le funzioni per 
 *  gestire i parametri dello schema IBRS.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */

#include "lib-ibrs-params.h"

void generate_params(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param,
                    int level, FILE* pairing_stream, FILE* param_stream, FILE* secret_stream) {
    assert(public_params);
	assert(secret_param);
	assert((level <= 128) && (level >= 80));

	pbc_param_t param;

    select_pbc_param_by_security_level(param, pbc_pairing_type_a, level, NULL);
    pairing_init_pbc_param(public_params->pairing, param);
	pbc_param_out_str(pairing_stream, param);
    
    //FOR DEBUGGING
    //infos_pairing(public_params->pairing);

    //INIT SCALAR X
    element_init_Zr(secret_param->x, public_params->pairing);
    element_random(secret_param->x);

    //INIT PARAM P
    element_init_G1(public_params->p, public_params->pairing);
    element_random(public_params->p);

    //INIT PARAM Ppub
    element_init_G1(public_params->ppub, public_params->pairing);
    element_mul_zn(public_params->ppub, public_params->p, secret_param->x);
	
    element_fprintf(param_stream, "%B\n%B", public_params->p, public_params->ppub);
	element_fprintf(secret_stream, "%B", secret_param->x);

	//INIT sha256 ctx
    sha256_init(&public_params->ctx);
	public_params->size_from_sec_level = level/4;

    pbc_param_clear(param);

    printf("Parametri creati.\n");
}

void load_params(ibrs_public_params_t* public_params, int level, FILE* pairing_stream, FILE* param_stream) {
    assert(public_params);
	assert((level <= 128) && (level >= 80));

	char* pairing_buffer; 
	long pairing_size;

	pairing_size = get_filesize(pairing_stream);
	pairing_buffer = calloc(pairing_size, sizeof(char));
	if(fread(pairing_buffer, sizeof(char),pairing_size, pairing_stream) != pairing_size) {
		printf("problema nella read di pairing_stream\n");
		exit(EXIT_FAILURE);
	}
	pairing_init_set_buf(public_params->pairing, pairing_buffer, pairing_size);
	
	//INIT PARAM P
    element_init_G1(public_params->p, public_params->pairing);
	
    //INIT PARAM Ppub
    element_init_G1(public_params->ppub, public_params->pairing);
	
	if(param_stream!=NULL){
        char *line[2];
        size_t len = 0;
   
		line[0] = NULL;
		len = 0;
		if(getline(&line[0], &len, param_stream) != -1){
			element_set_str(public_params->p, line[0], 10);
		}
		
		line[1] = NULL;
		len = 0;
		if(getline(&line[1], &len, param_stream) != -1){
			element_set_str(public_params->ppub, line[1], 10);
		}

        fclose(param_stream);
	}
    	
	//INIT sha256 ctx
    sha256_init(&public_params->ctx);
	public_params->size_from_sec_level = level/4;

	fclose(pairing_stream);
    free(pairing_buffer);

    printf("Parametri caricati.\n");
}

void load_params_with_secret(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param, int level, FILE* pairing_stream, FILE* param_stream, FILE* secret_stream) {
    assert(public_params);
	assert((level <= 128) && (level >= 80));

	char* pairing_buffer; 
	long pairing_size;

	pairing_size = get_filesize(pairing_stream);
	pairing_buffer = calloc(pairing_size, sizeof(char));
	if(fread(pairing_buffer, sizeof(char),pairing_size, pairing_stream) != pairing_size) {
		printf("problema nella read di pairing_stream\n");
		exit(EXIT_FAILURE);
	}
	pairing_init_set_buf(public_params->pairing, pairing_buffer, pairing_size);

	//INIT PARAM X
    element_init_Zr(secret_param->x, public_params->pairing);
	
	//INIT PARAM P
    element_init_G1(public_params->p, public_params->pairing);
	
    //INIT PARAM Ppub
    element_init_G1(public_params->ppub, public_params->pairing);
	
	if(param_stream!=NULL){
        char *line[2];
        size_t len = 0;
   
		line[0] = NULL;
		len = 0;
		if(getline(&line[0], &len, param_stream) != -1){
			element_set_str(public_params->p, line[0], 10);
		}
		
		line[1] = NULL;
		len = 0;
		if(getline(&line[1], &len, param_stream) != -1){
			element_set_str(public_params->ppub, line[1], 10);
		}

		fclose(param_stream);
	}

	if(secret_stream!=NULL){
		char *line[1];
		size_t len = 0;

		line[0] = NULL;
		len = 0;
		if(getline(&line[0], &len, secret_stream) != -1){
			element_set_str(secret_param->x, line[0], 10);
		}
		fclose(secret_stream);
	}
    	
	//INIT sha256 ctx
    sha256_init(&public_params->ctx);
	public_params->size_from_sec_level = level/4;

	fclose(pairing_stream);
    free(pairing_buffer);

    printf("Parametri caricati.\n");
}

void ibrs_params_clear(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param) {
    assert(public_params);
    assert(secret_param);

	element_clear(public_params->p);
    element_clear(public_params->ppub);
    pairing_clear(public_params->pairing);

	element_clear(secret_param->x);
}
