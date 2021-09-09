#define CKB_C_STDLIB_PRINTF
#define true 1
#define false 0
#define bool _Bool

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifndef CKB_USE_SIM
#include "ckb_syscalls.h"
#endif

#include "blst.h"
//#include "server.c"
#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      goto exit;           \
    }                      \
  } while (0)

#define CHECK(_code)    \
  do {                  \
    int code = (_code); \
    if (code != 0) {    \
      err = code;       \
      goto exit;        \
    }                   \
  } while (0)

#define COUNTOF(s) (sizeof(s) / sizeof(s[0]))

static void fill_random(void *buf, size_t count) {
  for (int i = 0; i < count; i++) {
    *(uint8_t *)buf++ = i % 256;
  }
}

const static uint8_t g_dst_label[] =
    "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const static size_t g_dst_label_len = 43;

static void sign(uint8_t *sig, const blst_scalar sk, const uint8_t *msg,
                 size_t msg_len) {
  blst_p2 msg_p2;
  blst_hash_to_g2(&msg_p2, msg, msg_len, g_dst_label, g_dst_label_len, NULL, 0);
  blst_p2 sig_p2;
  blst_p2_mult(&sig_p2, &msg_p2, sk.b, 256);
  blst_p2_compress(sig, &sig_p2);
}

static BLST_ERROR verify(const uint8_t *sig, const uint8_t *pk,
                         const uint8_t *msg, size_t msg_len) {
  BLST_ERROR err;
  blst_p1_affine pk_p1_affine;
  blst_p1_uncompress(&pk_p1_affine, pk);
  blst_p2_affine sig_p2_affine;
  blst_p2_uncompress(&sig_p2_affine, sig);

#if 1
  // using one-shot
  printf("using one-shot\n");
  err =
      blst_core_verify_pk_in_g1(&pk_p1_affine, &sig_p2_affine, true, msg,
                                msg_len, g_dst_label, g_dst_label_len, NULL, 0);
  CHECK(err);
#else
  // using pairing interface

  // pubkey must be checked
  // signature will be checked internally later.
  printf("using pairing interface\n");
  uint8_t ctx_buff[blst_pairing_sizeof()];

  bool in_g1 = blst_p1_affine_in_g1(&pk_p1_affine);
  CHECK2(in_g1, -1);

  blst_pairing *ctx = (blst_pairing *)ctx_buff;
  blst_pairing_init(ctx, true, g_dst_label, g_dst_label_len);
  err = blst_pairing_aggregate_pk_in_g1(ctx, &pk_p1_affine, &sig_p2_affine, msg,
                                        msg_len, NULL, 0);
  CHECK(err);
  blst_pairing_commit(ctx);

  bool b = blst_pairing_finalverify(ctx, NULL);
  CHECK2(b, -1);
#endif

exit:
  return err;
}

static void dump(const char *name, uint8_t *data, size_t len) {
  printf("const uint8_t %s[%zu] = ", name, len);
  printf("{");
  for (size_t i = 0; i < len; i++) {
    if (i != (len - 1)) {
      printf("0x%02X,", data[i]);
    } else {
      printf("0x%02X", data[i]);
    }
  }
  printf("};\n");
}

int verify_only(void) {
  const uint8_t sig[96] = {
      0xAC, 0xFC, 0x4E, 0x0B, 0x16, 0xCE, 0x56, 0x8C, 0x78, 0xBA, 0x3C, 0xCB,
      0xE9, 0xFA, 0x6F, 0x26, 0x23, 0x1B, 0xEF, 0x65, 0xBC, 0xDB, 0x67, 0x04,
      0xD9, 0x26, 0x46, 0x87, 0x09, 0xED, 0xFE, 0x31, 0x2C, 0x79, 0x67, 0xF1,
      0x01, 0x75, 0x4A, 0xF1, 0xC2, 0x28, 0xD5, 0x25, 0x68, 0xA1, 0x75, 0x4E,
      0x09, 0xE2, 0x93, 0x08, 0xCF, 0x1C, 0x9F, 0x11, 0x39, 0x13, 0xE3, 0x0C,
      0x59, 0x5E, 0xF5, 0x50, 0x02, 0x12, 0xB5, 0xBB, 0xE7, 0x9E, 0x47, 0xAD,
      0xE4, 0xFC, 0xB6, 0x5F, 0xAA, 0xE4, 0x87, 0x99, 0xAF, 0x72, 0xD5, 0x6B,
      0xEB, 0x2C, 0x38, 0xD6, 0xA3, 0xD0, 0x45, 0x56, 0xB1, 0xC0, 0x8E, 0xC2};
  const uint8_t pk[48] = {
      0x91, 0x12, 0xA0, 0x38, 0x6A, 0x23, 0x40, 0x71, 0x4B, 0xA0, 0xC6, 0xD2,
      0xDF, 0x23, 0x53, 0x77, 0xA8, 0x67, 0x9C, 0x38, 0x99, 0xD0, 0x3E, 0x6E,
      0xF0, 0x4D, 0xBA, 0x7A, 0x50, 0xEF, 0x49, 0xE5, 0xA1, 0xDC, 0x93, 0x10,
      0x5E, 0x93, 0x74, 0xE9, 0x3E, 0xD3, 0x01, 0xB6, 0x34, 0x87, 0xE1, 0x7C};
  const uint8_t msg[12] = {0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x2C,
                           0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64};
  BLST_ERROR ret = verify(sig, pk, msg, COUNTOF(msg));
  if (ret == BLST_SUCCESS) {
    printf("Success\n");
  } else {
    printf("Failed: %d\n", ret);
  }
  return ret;
}

static int sign_and_verify(void) {
  uint8_t seed[32] = {0};

  blst_scalar sk;
  blst_p1 pk_p1;
  uint8_t pk[48] = {0};
  uint8_t sig[96] = {0};

  fill_random(seed, COUNTOF(seed));
  blst_keygen(&sk, seed, sizeof(seed), NULL, 0);

  uint8_t msg[] = "hello, world";
  size_t msg_len = COUNTOF(msg) - 1;
  sign(sig, sk, msg, msg_len);

  blst_sk_to_pk_in_g1(&pk_p1, &sk);
  blst_p1_compress(pk, &pk_p1);

  //  dump("sig", sig, COUNTOF(sig));
  //  dump("pk", pk, COUNTOF(pk));
  //  dump("msg", msg, msg_len);
  BLST_ERROR ret = verify(sig, pk, msg, msg_len);
  if (ret == BLST_SUCCESS) {
    printf("Success\n");
  } else {
    printf("Failed: %d\n", ret);
  }
  return ret;
}

int main(int argc, const char *argv[]) {
#if 1
  return verify_only();
#else
  return sign_and_verify();
#endif
}
