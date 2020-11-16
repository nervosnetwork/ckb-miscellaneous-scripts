#include <assert.h>
#define ASSERT assert

#include "../c/rsa_sighash_all.c"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

int md_string(const mbedtls_md_info_t *md_info, const char *buf, size_t n,
              unsigned char *output);

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

int ecdsa_sighash_random(void);

int md_string(const mbedtls_md_info_t *md_info, const char *buf, size_t n,
              unsigned char *output) {
  int ret = -1;
  mbedtls_md_context_t ctx;

  if (md_info == NULL) return (MBEDTLS_ERR_MD_BAD_INPUT_DATA);

  mbedtls_md_init(&ctx);

  if ((ret = mbedtls_md_setup(&ctx, md_info, 0)) != 0) goto cleanup;

  if ((ret = mbedtls_md_starts(&ctx)) != 0) goto cleanup;

  if ((ret = mbedtls_md_update(&ctx, (const unsigned char *)buf, n)) != 0)
    goto cleanup;

  ret = mbedtls_md_finish(&ctx, output);

cleanup:
  mbedtls_md_free(&ctx);
  return ret;
}

typedef struct mbedtls_test_rnd_pseudo_info {
  uint32_t key[16];
  uint32_t v0, v1;
} mbedtls_test_rnd_pseudo_info;

int mbedtls_test_rnd_pseudo_rand(void *rng_state, unsigned char *output,
                                 size_t len) {
  for (size_t i = 0; i < len; i++) {
    output[i] = (unsigned char)rand();
  }
  return 0;
}

void srand(unsigned seed);
long time(long *);

int ecdsa_sighash_random(void) {
  int exit_code = 0;
  int id = MBEDTLS_ECP_DP_SECP256R1;
  Secp256r1Info info;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d, r, s;
  mbedtls_test_rnd_pseudo_info rnd_info;
  unsigned char buf[32];

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  srand(time(NULL));

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));
  memset(buf, 0, sizeof(buf));

  ASSERT(mbedtls_test_rnd_pseudo_rand(&rnd_info, buf, sizeof(buf)) == 0);
  ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
  ASSERT(mbedtls_ecp_gen_keypair(&grp, &d, &Q, &mbedtls_test_rnd_pseudo_rand,
                                 &rnd_info) == 0);

  ASSERT(mbedtls_ecdsa_sign(&grp, &r, &s, &d, buf, sizeof(buf),
                            &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);

  serialize_secp256r1info(&Q, &r, &s, &info);

  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  if (false) {
    mbedtls_ecp_point new_Q;
    mbedtls_mpi new_r;
    mbedtls_mpi new_s;

    deserialize_secp256r1info(&new_Q, &new_r, &new_s, &info);
    ASSERT(mbedtls_ecdsa_verify(&grp, buf, sizeof(buf), &new_Q, &new_r,
                                &new_s) == 0);
  } else {
    info.algorithm_id = CKB_VERIFY_SECP256R1;
    exit_code = validate_signature(NULL, (const unsigned char *)&info,
                                   sizeof(info), buf, sizeof(buf), NULL, NULL);
    CHECK(exit_code == 0, exit_code);
  }
  exit_code = CKB_SUCCESS;
exit:
  if (exit_code == CKB_SUCCESS) {
    mbedtls_printf("ecdsa_sighash_random() passed.\n");
  } else {
    mbedtls_printf("ecdsa_sighash_random() failed.\n");
  }
  return exit_code;
}

#define EXPONENT 65537

int fake_random_entropy_poll( void *data, unsigned char *output,
                             size_t len, size_t *olen ) {
  *output = (unsigned char)rand();
  *olen = len;
  return 0;
}

int gen_rsa_key(uint32_t key_size, mbedtls_rsa_context* rsa) {
  int exit_code = 0;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  const char *pers = "rsa_genkey";

  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );
  mbedtls_rsa_init( rsa, MBEDTLS_RSA_PKCS_V15, 0 );

  exit_code = mbedtls_entropy_add_source( &entropy, fake_random_entropy_poll,
                                          NULL, 32,
                                          MBEDTLS_ENTROPY_SOURCE_STRONG );
  CHECK(exit_code == 0, exit_code);

  exit_code = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers, strlen( pers ));
  CHECK(exit_code == 0, exit_code);

  exit_code = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_size, EXPONENT);
  CHECK(exit_code == 0, exit_code);

  exit_code = 0;

exit:
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
  return exit_code;
}

int rsa_sign(mbedtls_rsa_context* rsa, const uint8_t* hash, uint32_t hash_size, uint8_t* sig) {
  int exit_code = 0;

  unsigned char hash_result[MBEDTLS_MD_MAX_SIZE];
  mbedtls_mpi N, P, Q, E;
  mbedtls_test_rnd_pseudo_info rnd_info;

  memset( &rnd_info, 0, sizeof( mbedtls_test_rnd_pseudo_info ) );
  ASSERT( mbedtls_rsa_check_privkey( rsa ) == 0 );
  exit_code = mbedtls_rsa_pkcs1_sign( rsa, &mbedtls_test_rnd_pseudo_rand,
                                       &rnd_info, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_NONE,
                                       hash_size, hash, sig);
  CHECK(exit_code == 0, exit_code);
  exit_code = CKB_SUCCESS;
  exit:
  return exit_code;
}


int rsa_verify(mbedtls_rsa_context* rsa, const uint8_t* hash, uint32_t hash_size, const uint8_t* sig) {
  int exit_code = 0;
  ASSERT( mbedtls_rsa_check_pubkey(rsa) == 0);
  exit_code = mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE, hash_size, hash, sig);
  CHECK(exit_code == 0, exit_code);

  exit_code = 0;
  exit:
  return exit_code;
}

int rsa_random(void) {
  int exit_code = 0;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  uint32_t key_size = 1024;
  uint32_t byte_size = key_size/8;

  uint8_t hash[32] = {1,2,3,4};
  uint8_t sig[byte_size];
  mbedtls_rsa_context rsa;
  exit_code = gen_rsa_key(key_size, &rsa);
  CHECK(exit_code == 0, exit_code);

  exit_code = rsa_sign(&rsa, hash, sizeof(hash), sig);
  CHECK(exit_code == 0, exit_code);

  exit_code = rsa_verify(&rsa, hash, sizeof(hash), sig);
  CHECK(exit_code == 0, exit_code);

  exit_code = 0;
  exit:
  if (exit_code == CKB_SUCCESS) {
    mbedtls_printf("rsa_random() passed.\n");
  } else {
    mbedtls_printf("rsa_random() failed.\n");
  }
  return exit_code;
}

void export_public_key(const mbedtls_rsa_context* rsa, RsaInfo* info) {
  mbedtls_mpi N, E;
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);
  int ret = mbedtls_rsa_export(rsa, &N, NULL, NULL, NULL, &E);
  ASSERT(ret == 0);
  mbedtls_mpi_write_binary_le(&N, info->N, info->key_size/8);
  mbedtls_mpi_write_binary_le(&E, (unsigned char *)&info->E, sizeof(info->E));
}


int rsa_sighash_random(void) {
  int exit_code = 0;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  uint32_t key_size = 1024;
  uint32_t byte_size = key_size/8;

  uint8_t hash[32] = {1,2,3,4};
  uint8_t sig[byte_size];
  mbedtls_rsa_context rsa;
  exit_code = gen_rsa_key(key_size, &rsa);
  CHECK(exit_code == 0, exit_code);

  exit_code = rsa_sign(&rsa, hash, sizeof(hash), sig);
  CHECK(exit_code == 0, exit_code);


  RsaInfo info;
  info.algorithm_id = CKB_VERIFY_RSA;
  info.key_size = key_size;
  export_public_key(&rsa, &info);

  uint8_t* ptr = get_rsa_signature(&info);
  memcpy(ptr, sig, sizeof(sig));

  uint8_t output[20];
  size_t output_len = 20;
  exit_code = validate_signature(NULL, (uint8_t*)&info, sizeof(info), hash, sizeof(hash), output, &output_len);
  CHECK(exit_code == 0, exit_code);

  exit_code = 0;
  exit:
  if (exit_code == CKB_SUCCESS) {
    mbedtls_printf("rsa_sighash_random() passed.\n");
  } else {
    mbedtls_printf("rsa_sighash_random() failed.\n");
  }
  return exit_code;
}

int rsa_sighash_all(void) {
  int exit_code = 0;
  uint8_t output[BLAKE160_SIZE];

  exit_code = validate_rsa_sighash_all(output);
  CHECK(exit_code == ERROR_RSA_VERIFY_FAILED, exit_code);

  exit_code = 0;
  exit:
  if (exit_code == 0) {
    mbedtls_printf("rsa_sighash_all() passed. (Ignore the failed messages above)");
  } else {
    mbedtls_printf("rsa_sighash_all() failed.");
  }
  return exit_code;
}

int main(int argc, const char *argv[]) {
  int exit_code = 0;
  exit_code = ecdsa_sighash_random();
  CHECK(exit_code == 0, exit_code);

  exit_code = rsa_random();
  CHECK(exit_code == 0, exit_code);

  exit_code = rsa_sighash_random();
  CHECK(exit_code == 0, exit_code);

  exit_code = rsa_sighash_all();
  CHECK(exit_code == 0, exit_code);

  exit_code = 0;
  exit:
  return exit_code;
}
