#define CKB_C_STDLIB_PRINTF 
#include "stdio.h"
#include "ckb_syscalls.h"
#include "../libsig.h"
#include "libecc_helper.h"

static const u8 pub_key_buf[] = {
    0x00, 0x01, 0x04, 0xba, 0xdb, 0xfe, 0x20, 0x24, 0xcd, 0x71, 0x5d,
    0xd7, 0x0b, 0x51, 0x48, 0xa0, 0xcd, 0xf2, 0x8d, 0x5e, 0x1c, 0xb5,
    0x15, 0x71, 0xa2, 0x01, 0x89, 0xf1, 0xde, 0x5b, 0x37, 0x85, 0x86,
    0x6c, 0x41, 0x42, 0xb6, 0x11, 0x29, 0xea, 0x58, 0x3a, 0xf3, 0x27,
    0xe0, 0x3a, 0xdb, 0x7d, 0xab, 0x2d, 0x75, 0xb4, 0x7d, 0x3b, 0x8f,
    0x4a, 0x33, 0x8b, 0x0e, 0x1a, 0xf6, 0xa6, 0x29, 0x99, 0x0b, 0x72,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static const u8 sig_buf[] = {
    0x15, 0x1a, 0xfc, 0x76, 0x76, 0x77, 0xa6, 0xd7, 0x80, 0x24, 0x50,
    0xea, 0x08, 0x24, 0x1a, 0xf4, 0x1d, 0xed, 0x2d, 0x29, 0xc6, 0x6a,
    0x23, 0x1e, 0x49, 0x92, 0xe7, 0x83, 0xf2, 0x74, 0x1f, 0xa9, 0xae,
    0x9f, 0x17, 0xf1, 0x2d, 0x0e, 0x0f, 0xf5, 0x3a, 0x3d, 0x12, 0xba,
    0x93, 0x90, 0x59, 0x53, 0x02, 0x9e, 0x40, 0x61, 0xdc, 0x9a, 0xd3,
    0xb4, 0x37, 0x76, 0x31, 0x94, 0xe0, 0xc3, 0x9f, 0x62};

static const u8 msg_buf[] = {0x74, 0x65, 0x73, 0x74, 0x0a};

static const char *ec_name = "SECP256R1";

static const char *ec_sig_name = "ECDSA";

static const char *hash_algorithm = "SHA256";

static int string_to_params(const char *ec_name, const char *ec_sig_name,
                            ec_sig_alg_type *sig_type,
                            const ec_str_params **ec_str_p,
                            const char *hash_name, hash_alg_type *hash_type) {
  const ec_str_params *curve_params;
  const ec_sig_mapping *sm;
  const hash_mapping *hm;
  u32 curve_name_len;

  if (sig_type != NULL) {
    /* Get sig type from signature alg name */
    sm = get_sig_by_name(ec_sig_name);
    if (!sm) {
      printf("Error: signature type %s is unknown!\n", ec_sig_name);
      goto err;
    }
    *sig_type = sm->type;
  }

  if (ec_str_p != NULL) {
    /* Get curve params from curve name */
    curve_name_len = local_strlen((const char *)ec_name) + 1;
    if (curve_name_len > 255) {
      /* Sanity check */
      goto err;
    }
    curve_params =
        ec_get_curve_params_by_name((const u8 *)ec_name, (u8)curve_name_len);
    if (!curve_params) {
      printf("Error: EC curve %s is unknown!\n", ec_name);
      goto err;
    }
    *ec_str_p = curve_params;
  }

  if (hash_type != NULL) {
    /* Get hash type from hash alg name */
    hm = get_hash_by_name(hash_name);
    if (!hm) {
      printf("Error: hash function %s is unknown!\n", hash_name);
      goto err;
    }
    *hash_type = hm->type;
  }

  return 0;

err:
  return -1;
}

/*
 * Verify signature data
 */
static int verify_signature() {
  const ec_str_params *ec_str_p;
  ec_sig_alg_type sig_type;
  hash_alg_type hash_type;
  ec_pub_key pub_key;
  ec_params params;
  int ret;

  MUST_HAVE(ec_name != NULL);

  /************************************/
  /* Get parameters from pretty names */
  ret = string_to_params(ec_name, ec_sig_name, &sig_type, &ec_str_p,
                         hash_algorithm, &hash_type);
  if (ret) {
    printf("Error: error when getting ec parameter\n");
    goto err;
  }
  /* Import the parameters */
  import_params(&params, ec_str_p);

  ret = ec_structured_pub_key_import_from_buf(&pub_key, &params, pub_key_buf,
                                              sizeof(pub_key_buf), sig_type);
  if (ret) {
    printf("Error: error when importing public key from\n");
    goto err;
  }

  ret = ec_verify(sig_buf, sizeof(sig_buf), &pub_key, msg_buf, sizeof(msg_buf),
                  sig_type, hash_type);

  if (ret) {
    printf("Error: error while verifying signature\n");
    goto err;
  }

  return 0;

err:
  return ret;
}

int main() {
  printf("start main...");
  if (verify_signature()) {
    printf("Error: verification failed\n");
    return -1;
  }
  printf("signature verification succeeded\n");
  return 0;
}
