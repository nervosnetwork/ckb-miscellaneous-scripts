#include "libec.h"
#include "libsig.h"

/* We include the printf external dependency for printf output */
#include "print.h"
/* We include the time external dependency for performance measurement */
#include "time.h"

#include "rand.h"

/* TODO: Don't know why these are still needed */
void ext_printf(const char *_format, ...) {}

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

  /* Curve params */
  const ec_str_params *ec_str_p;

  /* Private key */
  const u8 *priv_key;
  u8 priv_key_len;

  /* Function returning a fixed random value */
  int (*nn_random)(nn_t out, nn_src_t q);

  /* Hash function */
  hash_alg_type hash_type;

  /* Message */
  const char *msg;
  u32 msglen;

  /* Expected signature and associated length */
  ec_alg_type sig_type;
  const u8 *exp_sig;
  u8 exp_siglen;

  /* Optional ancillary data */
  const u8 *adata;
  u16 adata_len;
} ec_test_case;

typedef enum {
  TEST_KEY_IMPORT_ERROR = 1,
  TEST_SIG_ERROR = 2,
  TEST_SIG_COMP_ERROR = 3,
  TEST_VERIF_ERROR = 4,
  TEST_ECDH_ERROR = 5,
  TEST_ECDH_COMP_ERROR = 6,
} test_err_kind;

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

static const ec_test_case decdsa_rfc6979_SECP256R1_SHA256_0_test_case = {
    .name = "DECDSA-SHA256/SECP256R1 0",
    .ec_str_p = &secp256r1_str_params,
    .priv_key = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key,
    .priv_key_len =
        sizeof(decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key),
    .nn_random = NULL,
    .hash_type = SHA256,
    .msg = "sample",
    .msglen = 6,
    .sig_type = DECDSA,
    .exp_sig = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_expected_sig,
    .exp_siglen =
        sizeof(decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_expected_sig),
    .adata = NULL,
    .adata_len = 0};

ATTRIBUTE_WARN_UNUSED_RET static int ec_test_verify(u8 *sig, u8 siglen,
                                                    const ec_pub_key *pub_key,
                                                    const ec_test_case *c) {
  /* If the algorithm supports streaming, we check that both the streaming and
   * non streaming modes produce the same result.
   */
  int ret, check;

  MUST_HAVE(sig != NULL, ret, err);
  MUST_HAVE(c != NULL, ret, err);

  ret = ec_verify(sig, siglen, pub_key, (const u8 *)(c->msg), c->msglen,
                  c->sig_type, c->hash_type, c->adata, c->adata_len);
  if (ret) {
    ret = -1;
    goto err;
  }
  ret = is_verify_streaming_mode_supported(c->sig_type, &check);
  EG(ret, err);
  if (check) {
    ret =
        generic_ec_verify(sig, siglen, pub_key, (const u8 *)(c->msg), c->msglen,
                          c->sig_type, c->hash_type, c->adata, c->adata_len);
    if (ret) {
      ret = -1;
      goto err;
    }
  }

  ret = 0;
err:
  return ret;
}

/*
 * Those functions respectively perform signature and verification tests
 * based the content of a given test case.
 */
ATTRIBUTE_WARN_UNUSED_RET static int
ec_test_sign(u8 *sig, u8 siglen, ec_key_pair *kp, const ec_test_case *c) {
  /* If the algorithm supports streaming, we check that both the streaming and
   * non streaming modes produce the same result.
   */
  int ret, check;

  MUST_HAVE(sig != NULL, ret, err);
  MUST_HAVE(c != NULL, ret, err);

  ret = _ec_sign(sig, siglen, kp, (const u8 *)(c->msg), c->msglen, c->nn_random,
                 c->sig_type, c->hash_type, c->adata, c->adata_len);
  EG(ret, err);
  ret = is_sign_streaming_mode_supported(c->sig_type, &check);
  EG(ret, err);
  if (check) {
    u8 sig_tmp[EC_MAX_SIGLEN];
    MUST_HAVE(siglen <= sizeof(sig_tmp), ret, err);
    ret = generic_ec_sign(sig_tmp, siglen, kp, (const u8 *)(c->msg), c->msglen,
                          c->nn_random, c->sig_type, c->hash_type, c->adata,
                          c->adata_len);
    EG(ret, err);
    ret = are_equal(sig, sig_tmp, siglen, &check);
    EG(ret, err);
    if (!check) {
      ret = -1;
      goto err;
    }
  }

  ret = 0;
err:
  return ret;
}

static int encode_error_value(const ec_test_case *c, test_err_kind failed_test,
                              u32 *err_val) {
  ec_curve_type ctype;
  ec_alg_type stype = c->sig_type;
  hash_alg_type htype = c->hash_type;
  test_err_kind etype = failed_test;
  int ret;

  MUST_HAVE((c != NULL) && (err_val != NULL), ret, err);

  ret = ec_get_curve_type_by_name(c->ec_str_p->name->buf,
                                  c->ec_str_p->name->buflen, &ctype);
  EG(ret, err);

  *err_val = (((u32)ctype << 24) | ((u32)stype << 16) | ((u32)htype << 8) |
              ((u32)etype));
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
  test_err_kind failed_test = TEST_KEY_IMPORT_ERROR;
  u8 sig[EC_MAX_SIGLEN];
  ec_params params;
  ec_key_pair kp;
  u8 siglen;
  int ret;
  int check = 0;

  MUST_HAVE((c != NULL), ret, err);

  ret = local_memset(&kp, 0, sizeof(kp));
  EG(ret, err);
  ret = local_memset(&params, 0, sizeof(params));
  EG(ret, err);
  ret = local_memset(sig, 0, sizeof(sig));
  EG(ret, err);

  ret = import_params(&params, c->ec_str_p);
  if (ret) {
    ext_printf("Error importing params\n");
    goto err;
  }

  /* Regular import if not EdDSA */
  ret = ec_key_pair_import_from_priv_key_buf(&kp, &params, c->priv_key,
                                             c->priv_key_len, c->sig_type);
  if (ret) {
    failed_test = TEST_KEY_IMPORT_ERROR;
    goto err;
  }

  siglen = c->exp_siglen;
  ret = ec_test_sign(sig, siglen, &kp, c);
  if (ret) {
    failed_test = TEST_SIG_ERROR;
    goto err;
  }

  ret = are_equal(sig, c->exp_sig, siglen, &check);
  EG(ret, err);
  if (!check) {
    ret = -1;
    failed_test = TEST_SIG_COMP_ERROR;
    goto err;
  }

  ret = ec_test_verify(sig, siglen, &(kp.pub_key), c);
  if (ret) {
    failed_test = TEST_VERIF_ERROR;
    goto err;
  }

  check = 0;

  /* Try a public key recovery from the signature and the message.
   * This is only possible for ECDSA.
   */
  if (check) {
    struct ec_sign_context sig_ctx;
    u8 digest[MAX_DIGEST_SIZE] = {0};
    u8 digestlen;
    ec_pub_key pub_key1;
    ec_pub_key pub_key2;
    nn_src_t cofactor = &(params.ec_gen_cofactor);
    int cofactorisone;
    const u8 *input[2] = {(const u8 *)(c->msg), NULL};
    u32 ilens[2] = {c->msglen, 0};
    /* Initialize our signature context only for the hash */
    ret = ec_sign_init(&sig_ctx, &kp, c->sig_type, c->hash_type, c->adata,
                       c->adata_len);
    EG(ret, err);
    /* Perform the hash of the data ourselves */
    ret = hash_mapping_callbacks_sanity_check(sig_ctx.h);
    EG(ret, err);
    ret = sig_ctx.h->hfunc_scattered(input, ilens, digest);
    EG(ret, err);
    digestlen = sig_ctx.h->digest_size;
    MUST_HAVE(digestlen <= sizeof(digest), ret, err);
    /* Check the cofactor */
    ret = nn_isone(cofactor, &cofactorisone);
    EG(ret, err);
    /* Compute the two possible public keys */
    ret = __ecdsa_public_key_from_sig(&pub_key1, &pub_key2, &params, sig,
                                      siglen, digest, digestlen, c->sig_type);
    if (ret) {
      ret = 0;
      check = -1;
      goto pubkey_recovery_warning;
    }
    /* Check equality with one of the two keys */
    ret = prj_pt_cmp(&(pub_key1.y), &(kp.pub_key.y), &check);
    EG(ret, err);
    if (check) {
      ret = prj_pt_cmp(&(pub_key2.y), &(kp.pub_key.y), &check);
      EG(ret, err);
    }
  pubkey_recovery_warning:
    if (check && cofactorisone) {
      ext_printf("[~] Warning: ECDSA recovered public key differs from "
                 "real one ...");
      ext_printf("This can happen with very low probability. Please check "
                 "the trace:\n");
      pub_key_print("pub_key1", &pub_key1);
      pub_key_print("pub_key2", &pub_key2);
      pub_key_print("pub_key", &(kp.pub_key));
      buf_print("digest", digest, digestlen);
      buf_print("sig", sig, siglen);
    }
  }
  ret = 0;

err:
  if (ret) {
    u32 ret_;
    ret = encode_error_value(c, failed_test, &ret_);
    EG(ret, err);
    ret = (int)ret_;
  }

  return ret;
}

int main() {
  int ret = ec_sig_known_vector_tests_one(
      &decdsa_rfc6979_SECP256R1_SHA256_0_test_case);
  if (ret) {
    ext_printf("ECDSA failed: %d\n", ret);
  }
  return ret;
}
