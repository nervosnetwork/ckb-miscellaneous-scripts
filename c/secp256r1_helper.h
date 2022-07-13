// Note this must be included, otherwise linker would fail
// /riscv/lib/gcc/riscv64-unknown-linux-gnu/9.2.0/../../../../riscv64-unknown-linux-gnu/bin/ld:
// warning: cannot find entry symbol _start; not setting start address
#include <stdlib.h>

#include <stdarg.h>
#include <stdio.h>

#include "lib_ecc_types.h"
#include "libec.h"
#include "libsig.h"

/* We include the printf external dependency for printf output */
#include "print.h"
/* We include the time external dependency for performance measurement */
#include "time.h"

#include "rand.h"

/* Print the buffer of a given size */
void buf_print(const char *msg, const u8 *buf, u16 buflen) {
  u32 i;

  if ((buf == NULL) || (msg == NULL)) {
    goto err;
  }

  printf("%s: ", msg);
  for (i = 0; i < (u32)buflen; i++) {
    printf("%02x", buf[i]);
  }
  printf("\n");

err:
  return;
}

/* TODO: Don't know why these are still needed */
void ext_printf(const char *format, ...) {
  // va_list arglist;
  // va_start(arglist, format);
  // vprintf(format, arglist);
  // va_end(arglist);
}

int get_random(unsigned char *buf, u16 len) {
  for (int i = 0; i < len; i++) {
    buf[i] = 0;
  }
  return 0;
}

int get_ms_time(u64 *time) {
  *time = 0;
  return 0;
}

typedef struct {
  ec_alg_type sig_algo;
  hash_alg_type hash_algo;
  ec_params ec_params;
} secp256r1_context_t;

int secp256r1_context_init(secp256r1_context_t *context) {
  context->sig_algo = DECDSA;
  context->hash_algo = SHA256;
  int ret = import_params(&context->ec_params, &secp256r1_str_params);
  return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_verify_signature(secp256r1_context_t context, const u8 *sig,
                           u8 siglen, const ec_pub_key *pub_key, const u8 *m,
                           u32 mlen) {
  int ret;
  MUST_HAVE(sig != NULL, ret, err);
  ret = ec_verify(sig, siglen, pub_key, m, mlen, context.sig_algo,
                  context.hash_algo, NULL, 0);
  if (ret) {
    const int temp_pub_key_buf_size = 64;
    u8 temp_pub_key_buf[temp_pub_key_buf_size];
    ec_pub_key_export_to_aff_buf(pub_key, temp_pub_key_buf,
                                 temp_pub_key_buf_size);
    buf_print("VM pub key", temp_pub_key_buf, temp_pub_key_buf_size);
    printf("VM signature verification failed: %d\n", ret);
    printf("VM siglen %d, mlen %d, sig_algo %d, hash_algo %d\n", siglen, mlen,
           context.sig_algo, context.hash_algo);
    buf_print("VM signature", sig, siglen);
    buf_print("VM message", m, mlen);
    ret = -1;
    goto err;
  }

  ret = 0;
err:
  return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_sign_message(secp256r1_context_t context, u8 *sig, u8 siglen,
                       ec_key_pair *kp, const u8 *m, u32 mlen) {
  int ret;

  MUST_HAVE(sig != NULL, ret, err);
  MUST_HAVE(kp != NULL, ret, err);
  MUST_HAVE(m != NULL, ret, err);

  ret = generic_ec_sign(sig, siglen, kp, m, mlen, NULL, context.sig_algo,
                        context.hash_algo, NULL, 0);
  EG(ret, err);

  ret = 0;
err:
  return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_recover_public_key_from_signature(secp256r1_context_t context,
                                            ec_pub_key *pub_key1,
                                            ec_pub_key *pub_key2, const u8 *sig,
                                            u8 siglen, const u8 *hash,
                                            u8 hsize) {
  return __ecdsa_public_key_from_sig(pub_key1, pub_key2, &context.ec_params,
                                     sig, siglen, hash, hsize,
                                     context.sig_algo);
}

ATTRIBUTE_WARN_UNUSED_RET int
secp256r1_pub_key_import_from_buf(secp256r1_context_t context,
                                  ec_pub_key *pub_key, const u8 *pub_key_buf,
                                  u8 pub_key_buf_len) {
  return ec_pub_key_import_from_buf(pub_key, &context.ec_params, pub_key_buf,
                                    pub_key_buf_len, context.sig_algo);
}

ATTRIBUTE_WARN_UNUSED_RET int secp256r1_pub_key_import_from_aff_buf(
    secp256r1_context_t context, ec_pub_key *pub_key, const u8 *pub_key_buf,
    u8 pub_key_buf_len) {
  return ec_pub_key_import_from_aff_buf(pub_key, &context.ec_params,
                                        pub_key_buf, pub_key_buf_len,
                                        context.sig_algo);
}

ATTRIBUTE_WARN_UNUSED_RET int
secp256r1_pub_key_export_to_buf(secp256r1_context_t context,
                                const ec_pub_key *pub_key, u8 *pub_key_buf,
                                u8 pub_key_buf_len) {
  return ec_pub_key_export_to_buf(pub_key, pub_key_buf, pub_key_buf_len);
};

ATTRIBUTE_WARN_UNUSED_RET int
secp256r1_pub_key_export_to_aff_buf(secp256r1_context_t context,
                                    const ec_pub_key *pub_key, u8 *pub_key_buf,
                                    u8 pub_key_buf_len) {
  return ec_pub_key_export_to_aff_buf(pub_key, pub_key_buf, pub_key_buf_len);
};

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_get_key_pair_from_priv_key_buf(secp256r1_context_t context,
                                         ec_key_pair *kp, const u8 *priv_key,
                                         u8 priv_key_len) {
  return ec_key_pair_import_from_priv_key_buf(kp, &context.ec_params, priv_key,
                                              priv_key_len, context.sig_algo);
}
