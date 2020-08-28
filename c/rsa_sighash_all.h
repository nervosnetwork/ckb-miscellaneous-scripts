#ifndef CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H
#define CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H

#include <stddef.h>
/**
 * This structure contains the following information:
 * 1) RSA Key Size
 * 2) RSA Public Key
 * 3) Real Signature data
 *
 * Because we need to use the same interfaces (see validate_signature) as
 * secp256k1, store 1) and 2) information alone with signature.
 */
typedef struct RsaInfo {
  // RSA Key Size, in bits. For example, 1024, 2048.
  // Normally we use 1024; Choose 2048 for safety.
  uint16_t key_size;

  // RSA public key, part E. It's normally very small, OK to use uint32_to hold
  // it. https://eprint.iacr.org/2008/510.pdf The choice e = 65537 = 2^16 + 1 is
  // especially widespread. Of the certificates observed in the UCSD TLS Corpus
  // [23] (which was obtained by surveying frequently-used TLS servers), 99.5%
  // had e = 65537, and all had e at most 32 bits.
  uint32_t E;

  // RSA public key, part N.
  // The public key is the combination of E and N.
  // But N is a very large number and need to use array to represent it.
  // The total length in byte is key_size/8 (The key_size is in bits).
  // The memory layout is the same as the field "p" of mbedtls_mpi type.
  uint8_t *N;

  // length of signature, in bytes.
  uint32_t sig_length;
  // pointer to signature
  uint8_t *sig;
} RsaInfo;
#endif  // CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H
