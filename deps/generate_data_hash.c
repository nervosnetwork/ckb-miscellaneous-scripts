#include <stdio.h>
#include <stdlib.h>
#include "blake2b.h"

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("Usage: %s <file name to hash> <hash variable name>\n", argv[0]);
    return 1;
  }

  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    return -1;
  }
  fseek(f, 0, SEEK_END);
  size_t s = ftell(f);
  fseek(f, 0, SEEK_SET);

  void *buffer = malloc(s);
  if (fread(buffer, s, 1, f) != 1) {
    free(buffer);
    return -2;
  }
  fclose(f);

  blake2b_state blake2b_ctx;
  uint8_t hash[32];
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, buffer, s);
  blake2b_final(&blake2b_ctx, hash, 32);

  free(buffer);

  printf("#ifndef CKB_%s_H_\n", argv[2]);
  printf("#define CKB_%s_H_\n", argv[2]);
  printf("static uint8_t %s[32] = {\n  ", argv[2]);
  for (int i = 0; i < 32; i++) {
    printf("%u", hash[i]);
    if (i != 31) {
      printf(", ");
    }
  }
  printf("\n};\n");
  printf("#endif\n");

  return 0;
}
