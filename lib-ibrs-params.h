#ifndef LIB_IBRS_GENPAR_H
#define LIB_IBRS_GENPAR_H
#define _GNU_SOURCE

#include "lib-ibrs-ga.h"

long get_filesize(FILE *fp);
void generate_params(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param, 
				int level, FILE* pairing_stream, FILE* param_stream, FILE* secret_stream);
void load_params(ibrs_public_params_t* public_params,int level, FILE* pairing_stream, FILE* param_stream);
void load_params_with_secret(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param, int level, 
				FILE* pairing_stream, FILE* param_stream, FILE* secret_stream);			
void ibrs_params_clear(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param);

#endif /* LIB_IBRS_GENPAR_H */