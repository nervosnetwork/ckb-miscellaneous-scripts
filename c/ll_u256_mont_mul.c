// make printf to work: by default, the function printf is not included.
#define CKB_C_STDLIB_PRINTF

// use deps/ckb-c-stdlib
#include <stdio.h>
#include <stdlib.h>

// printf will use syscalls "ckb_debug" to print message to console
#include <ckb_syscalls.h>

#define LOOP_COUNT 10000

__attribute__((noinline)) void
ll_u256_mont_mul(uint64_t rd[4], const uint64_t ad[4], const uint64_t bd[4],
                 const uint64_t Nd[4], uint64_t k0);

void buf_print(const char *msg, const unsigned char *buf, size_t buflen) {
  printf("%s: ", msg);
  for (size_t i = 0; i < buflen; i++) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}

int check_result(uint64_t *result, uint64_t *expected, size_t len) {
  buf_print("result", (const unsigned char *)result, len * sizeof(uint64_t));
  buf_print("expected", (const unsigned char *)expected,
            len * sizeof(uint64_t));
  for (size_t i = 0; i < len; i++) {
    if (result[i] != expected[i]) {
      return 1;
    }
  }
  return 0;
}

int main(int argc, const char *argv[]) {
  uint64_t result[4] = {0};
  uint64_t a[4] = {0x4fecd9c6bef4805b, 0xd0756fcc51b07b0f, 0x0ff21caf40d141c8,
                   0x13a1};
  buf_print("a", (const unsigned char *)a, sizeof(a));
  uint64_t b[4] = {0x416f50773146a5a8, 0x3d0688a3ae92febb, 0xb70671c25ec783df,
                   0x5c03};
  buf_print("b", (const unsigned char *)b, sizeof(b));
  const uint64_t N[4] = {0x0ea6dd724f352a8d, 0x68888ca48183dd72,
                         0x8fa0b8b4ada1a38b, 0x76e4};
  buf_print("b", (const unsigned char *)b, sizeof(b));
  uint64_t k = 0xfb9ab0f02a8457bb;

  printf("Testing asm version ...\n");
  printf("%lx\n", k);
  for (int i = 0; i < LOOP_COUNT; i++) {
    ll_u256_mont_mul(result, a, b, N, k);
  }
  uint64_t expected[4] = {0xe7f5addeb61a539a, 0x53bcacb7fd99f0f4,
                          0x471d58e78e2d6b00, 0x6fc7};
  return check_result(result, expected, 4);
}
