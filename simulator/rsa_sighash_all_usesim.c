#include <assert.h>
#define ASSERT assert

#include "../c/rsa_sighash_all.c"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

int md_string(const mbedtls_md_info_t *md_info, const char *buf, size_t n,
              unsigned char *output);

void dump_as_carray(uint8_t* ptr, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if ( i == (size - 1)) {
      mbedtls_printf("0x%02X\n", ptr[i]);
    } else {
      mbedtls_printf("0x%02X,", ptr[i]);
    }
  }
  mbedtls_printf("\n");
}

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

static uint32_t read_string(const char* str, uint8_t* buf, uint32_t buf_size) {
  size_t sig_len = strlen(str);
  const char *ptr = str;
  const char *end = str + sig_len;

  uint32_t i = 0;
  while (1) {
    unsigned char c = 0;
    int consumed = scan_hex(ptr, &c);
    if (consumed == 0) break;
    if (i >= buf_size) break;
    buf[i++] = (uint8_t)c;
    ptr += consumed * 2;
    if (ptr >= end) break;
  }
  return i;
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
  int err = 0;
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
//    dump_as_carray((uint8_t *)&info, sizeof(info));
//    dump_as_carray(buf, sizeof(buf));
    err = validate_signature(NULL, (const unsigned char *)&info,
                                   sizeof(info), buf, sizeof(buf), NULL, NULL);
    CHECK(err);
  }
  err = CKB_SUCCESS;
exit:
  if (err == CKB_SUCCESS) {
    mbedtls_printf("ecdsa_sighash_random() passed.\n");
  } else {
    mbedtls_printf("ecdsa_sighash_random() failed.\n");
  }
  return err;
}

#define EXPONENT 65537

int fake_random_entropy_poll( void *data, unsigned char *output,
                             size_t len, size_t *olen ) {
  *output = (unsigned char)rand();
  *olen = len;
  return 0;
}

int gen_rsa_key(uint32_t key_size, mbedtls_rsa_context* rsa) {
  int err = 0;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  const char *pers = "rsa_genkey";

  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );
  mbedtls_rsa_init( rsa, MBEDTLS_RSA_PKCS_V15, 0 );

  err = mbedtls_entropy_add_source( &entropy, fake_random_entropy_poll,
                                          NULL, 32,
                                          MBEDTLS_ENTROPY_SOURCE_STRONG );
  CHECK(err);

  err = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers, strlen( pers ));
  CHECK(err);

  err = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_size, EXPONENT);
  CHECK(err);

  err = 0;

exit:
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
  return err;
}

int rsa_sign(mbedtls_rsa_context* rsa, const uint8_t* hash, uint32_t hash_size, uint8_t* sig) {
  int err = 0;

  unsigned char hash_result[MBEDTLS_MD_MAX_SIZE];
  mbedtls_mpi N, P, Q, E;
  mbedtls_test_rnd_pseudo_info rnd_info;

  memset( &rnd_info, 0, sizeof( mbedtls_test_rnd_pseudo_info ) );
  ASSERT( mbedtls_rsa_check_privkey( rsa ) == 0 );
  err = mbedtls_rsa_pkcs1_sign( rsa, &mbedtls_test_rnd_pseudo_rand,
                                       &rnd_info, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_NONE,
                                       hash_size, hash, sig);
  CHECK(err);
  err = CKB_SUCCESS;
  exit:
  return err;
}


int rsa_verify(mbedtls_rsa_context* rsa, const uint8_t* hash, uint32_t hash_size, const uint8_t* sig) {
  int err = 0;
  ASSERT( mbedtls_rsa_check_pubkey(rsa) == 0);
  err = mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE, hash_size, hash, sig);
  CHECK(err);

  err = 0;
  exit:
  return err;
}

int rsa_random(void) {
  int err = 0;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  uint32_t key_size = 1024;
  uint32_t byte_size = key_size/8;

  uint8_t hash[32] = {1,2,3,4};
  uint8_t sig[byte_size];
  mbedtls_rsa_context rsa;
  err = gen_rsa_key(key_size, &rsa);
  CHECK(err);

  err = rsa_sign(&rsa, hash, sizeof(hash), sig);
  CHECK(err);

  err = rsa_verify(&rsa, hash, sizeof(hash), sig);
  CHECK(err);

  err = 0;
  exit:
  if (err == CKB_SUCCESS) {
    mbedtls_printf("rsa_random() passed.\n");
  } else {
    mbedtls_printf("rsa_random() failed.\n");
  }
  return err;
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
  int err = 0;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  uint32_t key_size = 1024;
  uint32_t byte_size = key_size/8;

  uint8_t hash[32] = {1,2,3,4};
  uint8_t sig[byte_size];
  mbedtls_rsa_context rsa;
  err = gen_rsa_key(key_size, &rsa);
  CHECK(err);

  err = rsa_sign(&rsa, hash, sizeof(hash), sig);
  CHECK(err);


  RsaInfo info;
  info.algorithm_id = CKB_VERIFY_RSA;
  info.key_size = key_size;
  export_public_key(&rsa, &info);

  uint8_t* ptr = get_rsa_signature(&info);
  memcpy(ptr, sig, sizeof(sig));

  uint8_t output[20];
  size_t output_len = 20;
  err = validate_signature(NULL, (uint8_t*)&info, sizeof(info), hash, sizeof(hash), output, &output_len);
  CHECK(err);

  err = 0;
  exit:
  if (err == CKB_SUCCESS) {
    mbedtls_printf("rsa_sighash_random() passed.\n");
  } else {
    mbedtls_printf("rsa_sighash_random() failed.\n");
  }
  return err;
}

int rsa_sighash_all(void) {
  int err = 0;
  uint8_t output[BLAKE160_SIZE];

  err = validate_rsa_sighash_all(output);
  CHECK2(err == ERROR_RSA_VERIFY_FAILED, err);

  err = 0;
  exit:
  if (err == 0) {
    mbedtls_printf("rsa_sighash_all() passed. (Ignore the failed messages above)");
  } else {
    mbedtls_printf("rsa_sighash_all() failed.");
  }
  return err;
}

int d1_test(void) {
  int err = 0;
  uint8_t msg3[] = {0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89,0x9a,0xab,0xbc,0xcd};

  ISO9796D1Encoding enc;
  enc.pad_bits = 4;
  enc.bit_size = 512;

  uint32_t block_length = d1_cal_block_length(&enc);
  uint32_t real_block_length = block_length;
  uint8_t block[block_length];

  err = d1_encode(&enc, msg3, 0, sizeof(msg3), block, block_length, &real_block_length);
  uint8_t new_block[real_block_length];

  CHECK(err);
  uint32_t new_block_length = real_block_length;
  err = d1_decode(&enc, block, real_block_length, new_block, &new_block_length);
  CHECK(err);

  err = memcmp(new_block, msg3, sizeof(msg3));
  CHECK2(err == 0, -1);

  err = 0;
  exit:
  return err;
}

int d1_test2(void) {
  int err = 0;
  const char* N_str = "9cf68418644a5418529373350bafd57ddbf5626527b95e8ea3217d8dac8fbcb7db107eda5e47979b7e4343ed6441950f7fbd921075579104ba081f1a9af950b4c0ee67c2eef2068d9fe2d9d0cfdcbb9be7066e19cc945600e9fd41fc50e771f437ce4bdde63e7acf2a828a4bf38b9f907a252b3dfef550919da1819033f9c619";
  const char* E_str = "10001";
  const char* sig_str  = "760967295823DCFA837B64674EC8F140271C184252BA824C6655648ECCDD33C6011536998B81136CC24BC29F9AE05C8C49D605AADC8232BA921B31A99D75E60E4F3117192FEA047BB3A3EFB7C94F1A1814A4C9E54BD7AE3D9C2FE6C44E39A2DFDE3030FD313C4828C4F340045FC7B98A12AA5966047478013E83D7E9EB4AABEF";

  mbedtls_rsa_context rsa;
  mbedtls_mpi N;
  mbedtls_mpi E;

  uint8_t sig[128];
  uint8_t msg[128];
  uint8_t new_block[128];
  uint32_t sig_size = 0;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);

  mbedtls_mpi_read_string(&N, 16, N_str);
  mbedtls_mpi_read_string(&E, 16, E_str);
  mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
  mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E);

  sig_size = read_string(sig_str, sig, sizeof(sig));
  ASSERT(sig_size == 128);
  err = mbedtls_rsa_public(&rsa, sig, msg);
  CHECK(err);

  err = 0;
  exit:
  return err;
}


int main(int argc, const char *argv[]) {
  int err = 0;
  err = ecdsa_sighash_random();
  CHECK(err);

  err = rsa_random();
  CHECK(err);

  err = rsa_sighash_random();
  CHECK(err);

  err = rsa_sighash_all();
  CHECK(err);

  err = d1_test();
  CHECK(err);

  err = d1_test2();
  CHECK(err);

  err = 0;
  exit:
  return err;
}
