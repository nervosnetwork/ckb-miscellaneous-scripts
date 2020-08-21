//
// Created by xujiandong on 2020/8/21.
//

#ifndef CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H
#define CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H


#include <stdint.h>

/**
 * This structure contains the following information:
 * 1) RSA Key Size
 * 2) RSA Public Key
 * 3) Real Signature data
 *
 * Because we need to use the same interfaces (see validate_signature) as secp256k1,
 * store 1) and 2) information alone with signature.
 * May be a little confusion.
 */
typedef struct signature {
    // RSA Key Size, for example, 1024, 2048.
    uint16_t key_size;

    // RSA public key, part E.
    uint32_t E;
    // RSA public key, part N. Together with E, it's public key.
    // The total length in byte is key_size/8.
    // remember that RSA Key Size is in bit.
    uint8_t* N;

    // length of signature
    uint32_t sig_length;
    // pointer to signature
    uint8_t* sig;
} signature_t;

#endif //CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H
