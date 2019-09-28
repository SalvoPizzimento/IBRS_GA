/** @file lib-ibrs-params.h
 *  @brief Prototipi dei parametri del Group Admin.
 *
 *  Contiene i prototipi per i parametri,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */

#ifndef LIB_IBRS_GENPAR_H
#define LIB_IBRS_GENPAR_H
#define _GNU_SOURCE

#include "lib-ibrs-ga.h"

/** @brief Funzione per generare i parametri dello schema e salvarli nei file.
 *  @param public_params parametri pubblici per lo schema crittografico
* 	@param secret_param parametro segreto per lo schema crittografico
 *  @param level livello di sicurezza crittografica
 *  @param pairing_stream file stream dove salvare il pairing
 *  @param param_stream file stream dove salvare i parametri
 *	@param secret_stream file stream dove salvare il parametro segreto
 */
void generate_params(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param, 
				int level, FILE* pairing_stream, FILE* param_stream, FILE* secret_stream);

/** @brief Funzione per caricare i soli parametri pubblici dello schema da un file.
 *  @param public_params parametri pubblici per lo schema crittografico
 *  @param level livello di sicurezza crittografica
 *  @param pairing_stream file stream da cui caricare il pairing
 *  @param param_stream file stream da cui caricare i parametri
 */
void load_params(ibrs_public_params_t* public_params, int level, FILE* pairing_stream, FILE* param_stream);

/** @brief Funzione per caricare i parametri pubblici e il parametro segreto dello schema da un file.
 *  @param public_params parametri pubblici per lo schema crittografico
 * 	@param secret_param parametro segreto per lo schema crittografico
 *  @param level livello di sicurezza crittografica
 *  @param pairing_stream file stream da cui caricare il pairing
 *  @param param_stream file stream da cui caricare i parametri
* 	@param param_stream file stream da cui caricare il parametro segreto
 */
void load_params_with_secret(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param, int level, 
				FILE* pairing_stream, FILE* param_stream, FILE* secret_stream);			

/** @brief Funzione per liberare la struttura parametri.
 *  @param public_params parametri pubblici da liberare
 */
void ibrs_params_clear(ibrs_public_params_t* public_params, ibrs_secret_param_t* secret_param);

#endif /* LIB_IBRS_GENPAR_H */