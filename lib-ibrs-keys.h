/** @file lib-ibrs-keys.h
 *  @brief Prototipi delle chiavi del Group Admin.
 *
 *  Contiene i prototipi per le chiavi,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */

#ifndef LIB_IBRS_GENKEY_H
#define LIB_IBRS_GENKEY_H
#define _GNU_SOURCE

#include "lib-ibrs-ga.h"

/** @brief Funzione per creare una coppia di chiavi e salvarla in un file.
 *  @param public_params parametri pubblici per lo schema crittografico
 *  @param secret_param parametro segreto per lo schema crittografico
 *  @param keys struttura dove inserire la coppia di chiavi
 *  @param identity identità per cui creare la coppia di chiavi
 *  @param keys_stream file stream dove salvare la coppia di chiavi
 */
void ibrs_keys_gen(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param, ibrs_key_pair* keys, char* identity, FILE* keys_stream);

/** @brief Funzione per liberare la struttura chiavi.
 *  @param keys struttura da liberare
 */
void ibrs_keys_clear(ibrs_key_pair* keys);

#endif /* LIB_IBRS_GENKEY_H */