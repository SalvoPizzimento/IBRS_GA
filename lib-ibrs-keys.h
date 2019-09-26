#ifndef LIB_IBRS_GENKEY_H
#define LIB_IBRS_GENKEY_H
#define _GNU_SOURCE

#include "lib-ibrs-ga.h"

void ibrs_keys_gen(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param, ibrs_key_pair* keys, char* identity, FILE* keys_stream);
void ibrs_keys_clear(ibrs_key_pair* keys);

#endif /* LIB_IBRS_GENKEY_H */