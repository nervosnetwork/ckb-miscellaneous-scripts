// Note this must be included, otherwise linker would fail
// /riscv/lib/gcc/riscv64-unknown-linux-gnu/9.2.0/../../../../riscv64-unknown-linux-gnu/bin/ld:
// warning: cannot find entry symbol _start; not setting start address
#include <stdlib.h>

#include "lib_ecc_types.h"
#include "libec.h"
#include "libsig.h"
#include "sig/ec_key.h"

#include "print.h"
#include "rand.h"
#include "time.h"

/* TODO: Don't know why these are still needed */
void ext_printf(const char *_format, ...) {
  // vprintf is not available in ckb-c-stdlib
  // Copied from https://stackoverflow.com/a/23789807
  void *arg = __builtin_apply_args();
  void *ret = __builtin_apply((void *)printf, arg, 100);
  __builtin_return(ret);
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

/* A test is fully defined by the attributes pointed in this structure. */
typedef struct {
  /* Test case name */
  const char *name;

  /* Public key */
  const u8 *pub_key;
  u8 pub_key_len;

  /* Private key */
  const u8 *priv_key;
  u8 priv_key_len;

  /* Message */
  const char *msg;
  u32 msglen;

  /* Expected signature */
  const u8 *exp_sig;
} ec_test_case;

typedef enum {
  ERROR_UNREACHABLE = 1,
  ERROR_OTHER = 2,
  ERROR_KEY_IMPORT = 3,
  ERROR_KEY_EXPORT = 4,
  ERROR_SIG = 5,
  ERROR_SIG_COMP = 6,
  ERROR_VERIF = 7,
} test_err_kind;

static const u8 EXP_SIGLEN = 64;
static const ec_alg_type SIG_ALGO = DECDSA;
static const hash_alg_type HASH_ALGO = SHA256;
// Use it directly, do not reassign it.
// Otherwise there will be some unfathomable error.
static ec_params SECP256R1_EC_PARAMS;

static const u8 decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_expected_sig[] = {
    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd,
    0x9c, 0xd4, 0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa,
    0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16, 0xf7,
    0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1,
    0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4,
    0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8};

static const u8 decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key[] = {
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
    0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
    0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};

static const u8 decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_pub_key[] = {
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb,
    0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
    0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79,
    0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9,
    0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f,
    0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};

static const u8 test_signature[] = {
    0x80, 0x22, 0x17, 0x2e, 0xe9, 0x1b, 0xdc, 0xd5, 0x11, 0x22, 0x57,
    0x0f, 0x96, 0x2e, 0x9c, 0x81, 0xdf, 0x93, 0xc7, 0x0f, 0x9c, 0xe3,
    0xce, 0x53, 0x48, 0xb5, 0x7d, 0x5d, 0xd6, 0xf6, 0x7f, 0x04, 0xc0,
    0x7f, 0x55, 0xee, 0xcd, 0xf8, 0xcd, 0x83, 0x6a, 0x6f, 0xc4, 0x7e,
    0x7e, 0xde, 0xb7, 0x67, 0x3e, 0x14, 0x6f, 0x29, 0x4b, 0x8b, 0x7d,
    0x5a, 0x36, 0xb5, 0x16, 0xe7, 0x01, 0x5e, 0xad, 0x52};

static const u8 test_message[] = {
    0xf5, 0x5b, 0x56, 0x81, 0x74, 0x46, 0x9c, 0x14, 0xfd, 0xb3, 0x60,
    0x88, 0xde, 0xfd, 0x3d, 0xcb, 0x0a, 0xd5, 0xa8, 0xba, 0x6b, 0x34,
    0x58, 0xd0, 0x83, 0x50, 0xa2, 0x29, 0xdf, 0xf7, 0x99, 0xcf};

static const u8 test_priv_key[] = {
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
    0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
    0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};

static const u8 test_pub_key[] = {
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb,
    0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
    0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79,
    0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9,
    0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f,
    0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};

static const ec_test_case decdsa_rfc6979_SECP256R1_SHA256_0_test_case = {
    .name = "DECDSA-SHA256/SECP256R1 0",
    .pub_key = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_pub_key,
    .pub_key_len =
        sizeof(decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_pub_key),
    .priv_key = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key,
    .priv_key_len =
        sizeof(decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key),
    .msg = "sample",
    .msglen = 6,
    .exp_sig = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_expected_sig,
};

static const ec_test_case my_test_case = {
    .name = "DECDSA-SHA256/SECP256R1 0",
    .pub_key = test_pub_key,
    .pub_key_len = sizeof(test_pub_key),
    .priv_key = test_priv_key,
    .priv_key_len = sizeof(test_priv_key),
    .msg = (const char *)test_message,
    .msglen = 32,
    .exp_sig = test_signature,
};

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_get_key_pair_from_priv_key_buf(ec_key_pair *kp, const u8 *priv_key,
                                         u8 priv_key_len) {
  return ec_key_pair_import_from_priv_key_buf(kp, &SECP256R1_EC_PARAMS,
                                              priv_key, priv_key_len, SIG_ALGO);
}

ATTRIBUTE_WARN_UNUSED_RET static int secp256r1_sign_message(u8 *sig, u8 siglen,
                                                            ec_key_pair *kp,
                                                            const u8 *m,
                                                            u32 mlen) {
  int ret;

  MUST_HAVE(sig != NULL, ret, err);
  MUST_HAVE(kp != NULL, ret, err);
  MUST_HAVE(m != NULL, ret, err);

  ret = generic_ec_sign(sig, siglen, kp, m, mlen, NULL, SIG_ALGO, HASH_ALGO,
                        NULL, 0);
  EG(ret, err);

  ret = 0;
err:
  return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_verify_signature(u8 *sig, u8 siglen, const ec_pub_key *pub_key,
                           const u8 *m, u32 mlen) {
  int ret;
  MUST_HAVE(sig != NULL, ret, err);
  MUST_HAVE(pub_key != NULL, ret, err);
  MUST_HAVE(m != NULL, ret, err);
  ext_printf("siglen %d, mlen %d, sig_algo %d, hash_algo %d\n", siglen, mlen,
             SIG_ALGO, HASH_ALGO);
  buf_print("signature", sig, siglen);
  buf_print("message", m, mlen);
  ret = ec_verify(sig, siglen, pub_key, m, mlen, SIG_ALGO, HASH_ALGO, NULL, 0);
  if (ret) {
    ext_printf("verification FAILED\n");
    ret = -1;
    goto err;
  }

  ret = 0;
err:
  return ret;
}

/*
 * ECC generic self tests (sign/verify on known test vectors). Returns
 * 0 if given test succeeded, or a non-zero value otherwise. In that
 * case, the value encodes the information on what went wrong as
 * described above.
 */
ATTRIBUTE_WARN_UNUSED_RET static int
ec_sig_known_vector_tests_one(const ec_test_case *c) {
  u8 sig[EC_MAX_SIGLEN];
  const u8 buf_size = 64;
  u8 temp_buf[buf_size];
  ec_key_pair kp;
  int ret;
  int check = 0;

  MUST_HAVE((c != NULL), ret, err);

  ret = local_memset(&kp, 0, sizeof(kp));
  EG(ret, err);
  ret = local_memset(sig, 0, sizeof(sig));
  EG(ret, err);

  ret = secp256r1_get_key_pair_from_priv_key_buf(&kp, c->priv_key,
                                                 c->priv_key_len);
  if (ret) {
    ret = ERROR_KEY_IMPORT;
    goto err;
  }

  // Dump information
  {
    pub_key_print("pub_key", &kp.pub_key);
    priv_key_print("priv_key", &kp.priv_key);
    if (ec_pub_key_export_to_aff_buf(&kp.pub_key, temp_buf, buf_size)) {
      ext_printf("exporting public key to buffer FAILED");
      ret = ERROR_KEY_EXPORT;
      goto err;
    }
    buf_print("exported public key", temp_buf, buf_size);
    if (c->pub_key) {
      buf_print("expected public key", c->pub_key, c->pub_key_len);
    }
  }

  ret = secp256r1_sign_message(sig, EXP_SIGLEN, &kp,
                               (const unsigned char *)c->msg, c->msglen);
  if (ret) {
    ret = ERROR_SIG;
    goto err;
  }

  ret = are_equal(sig, c->exp_sig, EXP_SIGLEN, &check);
  EG(ret, err);
  if (!check) {
    ret = ERROR_SIG_COMP;
    goto err;
  }

  ret = secp256r1_verify_signature(sig, EXP_SIGLEN, &(kp.pub_key),
                                   (const unsigned char *)c->msg, c->msglen);
  if (ret) {
    ret = ERROR_VERIF;
    goto err;
  }

  // ALso verify signature from specified public key
  if (c->pub_key) {
    ext_printf("Verifying with specified public key\n");
    ec_pub_key pk;
    if (ec_pub_key_import_from_aff_buf(&pk, &SECP256R1_EC_PARAMS, c->pub_key,
                                       c->pub_key_len, SIG_ALGO)) {
      ext_printf("importing public key from buffer FAILED\n");
      ret = ERROR_KEY_IMPORT;
      goto err;
    }
    if (secp256r1_verify_signature(sig, EXP_SIGLEN, &pk,
                                   (const unsigned char *)c->msg, c->msglen)) {
      ext_printf("verifying signature with fixed public key FAILED\n");
      ret = ERROR_VERIF;
      goto err;
    }

    // Export and import public key and then run verification once more
    {
      const u8 buf_size = 64;
      u8 temp_buf[buf_size];
      int r = local_memset(&temp_buf, 0, sizeof(temp_buf));
      if (r) {
        ret = ERROR_OTHER;
        goto err;
      }
      if (ec_pub_key_export_to_aff_buf(&pk, temp_buf, buf_size)) {
        ext_printf("Exporting public key to buffer FAILED\n");
        ret = ERROR_OTHER;
        goto err;
      }
      if (ec_pub_key_import_from_aff_buf(&pk, &SECP256R1_EC_PARAMS, c->pub_key,
                                         c->pub_key_len, SIG_ALGO)) {
        ext_printf("importing public key from buffer FAILED\n");
        ret = ERROR_KEY_IMPORT;
        goto err;
      }
      if (secp256r1_verify_signature(
              sig, EXP_SIGLEN, &pk, (const unsigned char *)c->msg, c->msglen)) {
        ext_printf("verifying signature with fixed public key FAILED\n");
        ret = ERROR_VERIF;
        goto err;
      }
    }
  }

  ret = 0;

err:
  if (ret) {
    ext_printf("%s failed: ret %d\n", __func__, ret);
  }
  return ret;
}

int main() {
  int ret;
  ret = import_params(&SECP256R1_EC_PARAMS, &secp256r1_str_params);
  EG(ret, err);
  ret = ec_sig_known_vector_tests_one(
      &decdsa_rfc6979_SECP256R1_SHA256_0_test_case);
  EG(ret, err);
  ret = ec_sig_known_vector_tests_one(&my_test_case);
  EG(ret, err);
err:
  if (ret) {
    ext_printf("ECDSA FAILED: %d\n", ret);
  }
  return ret;
}
