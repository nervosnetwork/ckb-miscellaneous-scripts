#include "libec.h"
#include "libsig.h"

#include "secp256r1_helper.h"

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

static const u8 test_pub_key[] = {
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb,
    0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
    0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79,
    0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9,
    0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f,
    0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};

int main() {
  secp256r1_context_t context;
  if (secp256r1_context_init(&context)) {
    return -1;
  }

  ec_pub_key pub_key;
  if (secp256r1_pub_key_import_from_aff_buf(&context, &pub_key, test_pub_key,
                                            sizeof(test_pub_key))) {
    return -2;
  }

  if (secp256r1_verify_signature(&context, test_signature,
                                 sizeof(test_signature), &pub_key, test_message,
                                 sizeof(test_message))) {
    return -3;
  };

  return 0;
}
