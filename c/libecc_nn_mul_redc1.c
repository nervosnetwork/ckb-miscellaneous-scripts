// make printf to work: by default, the function printf is not included.
#define CKB_C_STDLIB_PRINTF

// use deps/ckb-c-stdlib
#include <stdio.h>
#include <stdlib.h>

// printf will use syscalls "ckb_debug" to print message to console
#include <ckb_syscalls.h>

#include "../libsig.h"

#ifdef VERBOSE_INNER_VALUES
#include "../external_deps/print.h"
#include "../utils/dbg_sig.h"
#endif

#include "libecc_helper.h"

#define LOOP_COUNT 10

/*
 * montgomery multiplication test with fp256
int main(int argc, const char *argv[]) {
  uint64_t expected[4] = {0xe7f5addeb61a539a, 0x53bcacb7fd99f0f4,
                          0x471d58e78e2d6b00, 0x6fc7};
  uint64_t result[4] = {0};
  uint64_t a[4] = {0x4fecd9c6bef4805b, 0xd0756fcc51b07b0f, 0x0ff21caf40d141c8,
                   0x13a1};
  uint64_t b[4] = {0x416f50773146a5a8, 0x3d0688a3ae92febb, 0xb70671c25ec783df,
                   0x5c03};
  const uint64_t N[4] = {0x0ea6dd724f352a8d, 0x68888ca48183dd72,
                         0x8fa0b8b4ada1a38b, 0x76e4};
  uint64_t k = ll_invert_limb(N[0]);

  printf("%lx\n", k);
  ll_u256_mont_mul(result, a, b, N, k);
  check_result(result, expected, 4);
  return 0;
}
*/

const size_t nn_buf_size = 256 / 8;

__attribute__((always_inline)) inline void dump_nn(char *m, nn_src_t a) {
#ifdef VERBOSE_INNER_VALUES
  u8 tmp_buf[nn_buf_size];
  dbg_nn_print(m, a);
  nn_export_to_buf((u8 *)&tmp_buf, nn_buf_size, a);
  dbg_buf_print(m, &tmp_buf);
  dbg_buf_print("a", &tmp_buf);
#else
  const unsigned char *buf = (const unsigned char *)a->val;
  printf("%s: ", m);
  for (size_t i = 0; i < nn_buf_size; i++) {
    printf("%02x", buf[i]);
  }
  printf("\n");
#endif
}

int main() {
  static const u8 a_buf[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0xa1,
                             0x0f, 0xf2, 0x1c, 0xaf, 0x40, 0xd1, 0x41, 0xc8,
                             0xd0, 0x75, 0x6f, 0xcc, 0x51, 0xb0, 0x7b, 0x0f,
                             0x4f, 0xec, 0xd9, 0xc6, 0xbe, 0xf4, 0x80, 0x5b};
  static const u8 b_buf[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x03,
                             0xb7, 0x06, 0x71, 0xc2, 0x5e, 0xc7, 0x83, 0xdf,
                             0x3d, 0x06, 0x88, 0xa3, 0xae, 0x92, 0xfe, 0xbb,
                             0x41, 0x6f, 0x50, 0x77, 0x31, 0x46, 0xa5, 0xa8};
  static const u8 N_buf[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xe4,
                             0x8f, 0xa0, 0xb8, 0xb4, 0xad, 0xa1, 0xa3, 0x8b,
                             0x68, 0x88, 0x8c, 0xa4, 0x81, 0x83, 0xdd, 0x72,
                             0x0e, 0xa6, 0xdd, 0x72, 0x4f, 0x35, 0x2a, 0x8d};
  nn a;
  // buf should be in the big endian format
  nn_init_from_buf(&a, a_buf, nn_buf_size);

  nn b;
  nn_init_from_buf(&b, b_buf, nn_buf_size);

  nn N;
  nn_init_from_buf(&N, N_buf, nn_buf_size);

  word_t k = 0xfb9ab0f02a8457bb;

  dump_nn("a", &a);
  dump_nn("b", &b);
  dump_nn("N", &N);

  nn out;
  nn_zero(&out);

  for (int i = 0; i < LOOP_COUNT; i++) {
    nn_mul_redc1(&out, &a, &b, &N, k);
  }

  dump_nn("out", &out);
  return 0;
}
