#ifndef CKB_MISCELLANEOUS_SCRIPTS_INCLUDE_RSA_SECP256K1_H_
#define CKB_MISCELLANEOUS_SCRIPTS_INCLUDE_RSA_SECP256K1_H_
#include <stddef.h>

int load_prefilled_data(void *data, size_t *len);
int validate_signature_rsa(void *prefilled_data,
                           const uint8_t *signature_buffer,
                           size_t signature_size, const uint8_t *msg_buf,
                           size_t msg_size, uint8_t *output,
                           size_t *output_len);
int validate_signature_secp256k1(void *prefilled_data,
                           const uint8_t *signature_buffer,
                           size_t signature_size, const uint8_t *msg_buf,
                           size_t msg_size, uint8_t *output,
                           size_t *output_len);

#endif //CKB_MISCELLANEOUS_SCRIPTS_INCLUDE_RSA_SECP256K1_H_
