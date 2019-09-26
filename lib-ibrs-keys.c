#include "lib-ibrs-keys.h"

void ibrs_keys_gen(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param, ibrs_key_pair* keys, char* identity, FILE* keys_stream) {
	assert(public_params);
	assert(secret_param);
	assert(keys);
	assert(strlen(identity)>0);

	uint8_t digest[public_params->size_from_sec_level];

	element_init_G1(keys->sid, public_params->pairing);
	element_init_G1(keys->qid, public_params->pairing);

	sha256_update(&public_params->ctx, strlen(identity), (const uint8_t* ) identity);
	sha256_digest(&public_params->ctx, public_params->size_from_sec_level, digest);

	element_from_hash(keys->qid, digest, public_params->size_from_sec_level);
    element_mul_zn(keys->sid, keys->qid, secret_param->x);
	
	element_fprintf(keys_stream, "%B\n%B", keys->qid, keys->sid);

	printf("Keys created.\n");
}

void ibrs_keys_clear(ibrs_key_pair* keys) {
	assert(keys);
	
	element_clear(keys->sid);
	element_clear(keys->qid);
}