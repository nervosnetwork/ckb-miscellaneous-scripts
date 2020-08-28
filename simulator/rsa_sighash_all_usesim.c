#include "../c/rsa_sighash_all.c"

static unsigned char get_hex(unsigned char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  else
    return 0;
}

static int scan_hex(const char *s, unsigned char *value) {
  if (s[0] == '\0' || s[1] == '\0') return 0;

  unsigned char high_part = get_hex(s[0]);
  unsigned char low_part = get_hex(s[1]);

  *value = (high_part << 4) + low_part;
  return 1;
}

void mbedtls_mpi_dump(const char *prefix, const mbedtls_mpi *X) {
  size_t n;
  char s[1024];
  memset(s, 0, sizeof(s));

  mbedtls_mpi_write_string(X, 16, s, sizeof(s) - 2, &n);
  mbedtls_printf("%s%s\n", prefix, s);
}

void dup_buffer(const unsigned char *src, int src_len, unsigned char *dest,
                int dup_count) {
  for (int i = 0; i < dup_count; i++) {
    for (int j = 0; j < src_len; j++) {
      dest[i * src_len + j] = src[j];
    }
  }
}

int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  int exit_code = ERROR_RSA_ONLY_INIT;
  mbedtls_printf("Entering main()\n");
  const char *sig =
      "5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF48"
      "2546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE4820"
      "6DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C"
      "73D1EE248819479574028389376BD7F9FB4F5C9B";
  const char *msg = "hello,CKB!";
  unsigned char sig_buf[MBEDTLS_MPI_MAX_SIZE];
  const char *N =
      "A1D46FBA2318F8DCEF16C280948B1CF27966B9B47225ED2989F8D74B45BD36049C0AAB5A"
      "D0FF003553BA843C8E12782FC5873BB89A3DC84B883D25666CD22BF3ACD5B675969F8BEB"
      "FBCAC93FDD927C7442B178B10D1DFF9398E52316AAE0AF74E594650BDC3C670241D41868"
      "4593CDA1A7B9DC4F20D2FDC6F66344074003E211";
  // convert signature in plain string to binary
  size_t i = 0;
  size_t sig_len = strlen(sig);
  const char *sig_ptr = sig;
  const char *sig_end = sig + sig_len;

  while (1) {
    unsigned char c = 0;
    int consumed = scan_hex(sig_ptr, &c);
    if (consumed == 0) break;
    if (i >= (int)sizeof(sig_buf)) break;
    sig_buf[i++] = (unsigned char)c;
    sig_ptr += consumed * 2;
    if (sig_ptr >= sig_end) break;
  }

  int limbs_count = strlen(N) * 4 / 8;
  mbedtls_mpi_uint n_buff[limbs_count];
  mbedtls_mpi NN;
  mbedtls_mpi_init(&NN);
  // allocate memory manually, avoid using calloc
  NN.p = n_buff;
  NN.n = limbs_count;
  mbedtls_mpi_read_string(&NN, 16, N);

  RsaInfo info;
  info.key_size = 1024;
  info.sig = sig_buf;
  info.E = 65537;  // hex format: "010001"
  info.sig_length = sig_len / 2;

  uint8_t N_buff[info.key_size / 8];
  info.N = N_buff;
  mbedtls_mpi_write_binary_le(&NN, info.N, info.key_size / 8);

  uint8_t output;
  size_t output_len;
  int result = validate_signature(NULL, (const uint8_t *)&info, sizeof(info),
                                  (const uint8_t *)msg, strlen(msg), &output,
                                  &output_len);
  if (result == 0) {
    mbedtls_printf("validate signature passed\n");
  } else {
    mbedtls_printf("validate signature failed: %d\n", result);
    exit_code = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }

  msg = "hello, world!";
  int result2 = validate_signature(NULL, (const uint8_t *)&info, sizeof(info),
                                   (const uint8_t *)msg, strlen(msg), &output,
                                   &output_len);
  if (result2 == ERROR_RSA_VERIFY_FAILED) {
    mbedtls_printf("validate signature passed\n");
  } else {
    mbedtls_printf("(failed case) validate signature failed:%d\n", result);
    exit_code = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }

  info.key_size = 2048;
  unsigned char N2048[2048 / 8];
  dup_buffer(N_buff, 1024 / 8, N2048, 2);
  info.N = N2048;
  int result3 = validate_signature(NULL, (const uint8_t *)&info, sizeof(info),
                                   (const uint8_t *)msg, strlen(msg), &output,
                                   &output_len);
  if (result3 == ERROR_RSA_VERIFY_FAILED) {
    mbedtls_printf("validate signature (2048-bit) passed\n");
  } else {
    mbedtls_printf("validate signature (2048-bit) failed: %d\n", result);
    exit_code = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }

  info.key_size = 4096;
  unsigned char N4096[4096 / 8];
  dup_buffer(N_buff, 1024 / 8, N4096, 4);
  info.N = N4096;
  int result4 = validate_signature(NULL, (const uint8_t *)&info, sizeof(info),
                                   (const uint8_t *)msg, strlen(msg), &output,
                                   &output_len);
  if (result4 == ERROR_RSA_VERIFY_FAILED) {
    mbedtls_printf("validate signature (4096-bit) passed\n");
  } else {
    mbedtls_printf("validate signature (4096-bit) failed: %d\n", result);
    exit_code = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }
  exit_code = CKB_SUCCESS;
exit:
  if (exit_code != CKB_SUCCESS) {
    mbedtls_printf("Failed, check log!");
  }
  return exit_code;
}
