// # rsa_sighash_all
// same as secp256k1_blake2b_sighash_all_dual but with RSA (mbedtls)
#include "rsa_sighash_all.h"

#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/rsa.h"

#define CKB_SUCCESS 0
#define ERROR_ARGUMENTS_LEN (-1)
#define ERROR_ENCODING (-2)
#define ERROR_SYSCALL (-3)
#define ERROR_RSA_INVALID_PARAM1 (-40)
#define ERROR_RSA_INVALID_PARAM2 (-41)
#define ERROR_RSA_MDSTRING_FAILED (-42)
#define ERROR_RSA_VERIFY_FAILED (-43)
#define ERROR_RSA_ONLY_INIT (-44)
#define ERROR_RSA_INVALID_KEY_SIZE (-45)

#define RSA_VALID_KEY_SIZE1 1024
#define RSA_VALID_KEY_SIZE2 2048
#define RSA_VALID_KEY_SIZE3 4096

#define CHECK_PARAM(cond, code) \
  do {                          \
    if (!(cond)) {              \
      exit_code = code;         \
      goto exit;                \
    }                           \
  } while (0)

#if defined(USE_SIM)
#include <stdio.h>
#define mbedtls_printf printf
#else
#define mbedtls_printf(x, ...) (void)0
#endif
int md_string(const mbedtls_md_info_t *md_info, const unsigned char *buf,
              size_t n, unsigned char *output);
/**
 * Note: there is no prefilled data for RSA, it's only be used in secp256k1.
 * Always succeed.
 * @param data
 * @param len
 * @return
 */
__attribute__((visibility("default"))) int load_prefilled_data(void *data,
                                                               size_t *len) {
  (void)data;
  *len = 0;
  return CKB_SUCCESS;
}

/**
 *
 * @param prefilled_data ignore. Not used.
 * @param signature_buffer pointer to signature buffer. It is casted to type
 * "RsaInfo*"
 * @param signature_size size of signature_buffer. it should be exactly the same
 * as size of "RsaInfo".
 * @param message_buffer pointer to message buffer.
 * @param message_size size of message_buffer.
 * @param output ignore. Not used
 * @param output_len ignore. Not used.
 * @return
 */
__attribute__((visibility("default"))) int validate_signature(
    void *prefilled_data, const uint8_t *signature_buffer,
    size_t signature_size, const uint8_t *message_buffer, size_t message_size,
    uint8_t *output, size_t *output_len) {
  (void)prefilled_data;
  (void)output;
  (void)output_len;
  int ret;
  int exit_code = ERROR_RSA_ONLY_INIT;
  mbedtls_rsa_context rsa;
  unsigned char hash[32];
  RsaInfo *input_info = (RsaInfo *)signature_buffer;

  // for key size with 1024 bits, it uses 3444 bytes at most.
  // for key size with 4096 bits, it uses 6316 bytes at most.
  const int alloc_buff_size = 1024 * 7;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  CHECK_PARAM(input_info->key_size == RSA_VALID_KEY_SIZE1 ||
                  input_info->key_size == RSA_VALID_KEY_SIZE2 ||
                  input_info->key_size == RSA_VALID_KEY_SIZE3,
              ERROR_RSA_INVALID_KEY_SIZE);
  CHECK_PARAM(signature_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK_PARAM(message_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK_PARAM(signature_size == sizeof(RsaInfo), ERROR_RSA_INVALID_PARAM2);

  mbedtls_mpi_read_binary_le(&rsa.E, (const unsigned char *)&input_info->E,
                             sizeof(uint32_t));
  mbedtls_mpi_read_binary_le(&rsa.N, (const unsigned char *)input_info->N,
                             input_info->key_size / 8);
  rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

  ret = md_string(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), message_buffer,
                  message_size, hash);
  if (ret != 0) {
    mbedtls_printf("md_string failed: %d", ret);
    exit_code = ERROR_RSA_MDSTRING_FAILED;
    goto exit;
  }
  // note: hashlen = 20 is used for MD5, we can ignore it here for SHA256.
  ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                 MBEDTLS_MD_SHA256, 20, hash, input_info->sig);
  if (ret != 0) {
    mbedtls_printf("mbedtls_rsa_pkcs1_verify returned -0x%0x\n",
                   (unsigned int)-ret);
    exit_code = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }
  mbedtls_printf("\nOK (the signature is valid)\n");
  exit_code = CKB_SUCCESS;

exit:
  mbedtls_rsa_free(&rsa);
  return exit_code;
}

int md_string(const mbedtls_md_info_t *md_info, const unsigned char *buf,
              size_t n, unsigned char *output) {
  int ret = -1;
  mbedtls_md_context_t ctx;

  if (md_info == NULL) return (MBEDTLS_ERR_MD_BAD_INPUT_DATA);

  mbedtls_md_init(&ctx);

  if ((ret = mbedtls_md_setup(&ctx, md_info, 0)) != 0) goto cleanup;

  if ((ret = mbedtls_md_starts(&ctx)) != 0) goto cleanup;

  if ((ret = mbedtls_md_update(&ctx, buf, n)) != 0) goto cleanup;

  ret = mbedtls_md_finish(&ctx, output);

cleanup:
  mbedtls_md_free(&ctx);
  return ret;
}
