// # rsa_sighash_all
// same as secp256k1_blake2b_sighash_all_dual but with RSA (mbedtls)
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>

#include "rsa_sighash_all.h"

#include <string.h>

#include "blake2b.h"
#include "mbedtls/md.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/rsa.h"

#define CKB_SUCCESS 0
#define ERROR_ARGUMENTS_LEN (-1)
#define ERROR_ENCODING (-2)
#define ERROR_SYSCALL (-3)
#define ERROR_SCRIPT_TOO_LONG (-21)
#define ERROR_WITNESS_SIZE (-22)
#define ERROR_WRONG_SCRIPT_ARGS_LEN (-23)
#define ERROR_RSA_INVALID_PARAM1 (-40)
#define ERROR_RSA_INVALID_PARAM2 (-41)
#define ERROR_RSA_MDSTRING_FAILED (-42)
#define ERROR_RSA_VERIFY_FAILED (-43)
#define ERROR_RSA_ONLY_INIT (-44)
#define ERROR_RSA_INVALID_KEY_SIZE (-45)
#define ERROR_RSA_INVALID_BLADE2B_SIZE (-46)

#define RSA_VALID_KEY_SIZE1 1024
#define RSA_VALID_KEY_SIZE2 2048
#define RSA_VALID_KEY_SIZE3 4096

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20

#define PUBLIC_KEY_SIZE1 (RSA_VALID_KEY_SIZE1 / 8 + 4)
#define PUBLIC_KEY_SIZE2 (RSA_VALID_KEY_SIZE2 / 8 + 4)
#define PUBLIC_KEY_SIZE3 (RSA_VALID_KEY_SIZE3 / 8 + 4)

#define CHECK_PARAM(cond, code) \
  do {                          \
    if (!(cond)) {              \
      exit_code = code;         \
      goto exit;                \
    }                           \
  } while (0)

#if defined(CKB_USE_SIM)
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

uint8_t *get_rsa_signature(RsaInfo *info) {
  int length = info->key_size / 8;
  return (uint8_t *)&info->N[length];
}

uint32_t calculate_rsa_info_length(int key_size) { return 8 + key_size / 4; }

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
  CHECK_PARAM(
      signature_size == (size_t)calculate_rsa_info_length(input_info->key_size),
      ERROR_RSA_INVALID_PARAM2);
  CHECK_PARAM(*output_len >= BLAKE160_SIZE, ERROR_RSA_INVALID_BLADE2B_SIZE);

  mbedtls_mpi_read_binary_le(&rsa.E, (const unsigned char *)&input_info->E,
                             sizeof(uint32_t));
  mbedtls_mpi_read_binary_le(&rsa.N, input_info->N, input_info->key_size / 8);
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
                                 MBEDTLS_MD_SHA256, 20, hash,
                                 get_rsa_signature(input_info));
  if (ret != 0) {
    mbedtls_printf("mbedtls_rsa_pkcs1_verify returned -0x%0x\n",
                   (unsigned int)-ret);
    exit_code = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }

  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  // pub key hash = blake2b(key size + E + N)
  // here pub key = E+N
  blake2b_update(&blake2b_ctx, input_info, 8 + input_info->key_size / 8);
  unsigned char blake2b_hash[BLAKE2B_BLOCK_SIZE] = {0};
  blake2b_final(&blake2b_ctx, blake2b_hash, BLAKE2B_BLOCK_SIZE);

  *output_len = BLAKE160_SIZE;
  memcpy(output, blake2b_hash, BLAKE160_SIZE);

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

/*
 * The following code is to add RSA "validate all" method.
 * It mimic the behavior of validate_secp256k1_blake2b_sighash_all.
 */
#ifdef CKB_USE_SIM
#include "ckb_consts.h"
#include "ckb_syscall_sim.h"
#else
#include "ckb_syscalls.h"
#endif
#include "blake2b.h"
#include "blockchain.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define TEMP_SIZE 32768
#define ONE_BATCH_SIZE 32768

int load_and_hash_witness(blake2b_state *ctx, size_t index, size_t source) {
  uint8_t temp[ONE_BATCH_SIZE];
  uint64_t len = ONE_BATCH_SIZE;
  int ret = ckb_load_witness(temp, &len, 0, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  blake2b_update(ctx, (char *)&len, sizeof(uint64_t));
  uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
  blake2b_update(ctx, temp, offset);
  while (offset < len) {
    uint64_t current_len = ONE_BATCH_SIZE;
    ret = ckb_load_witness(temp, &current_len, offset, index, source);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    uint64_t current_read =
        (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
    blake2b_update(ctx, temp, current_read);
    offset += current_read;
  }
  return CKB_SUCCESS;
}

// Extract lock from WitnessArgs
int extract_witness_lock(uint8_t *witness, uint64_t len,
                         mol_seg_t *lock_bytes_seg) {
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t lock_seg = MolReader_WitnessArgs_get_lock(&witness_seg);

  if (MolReader_BytesOpt_is_none(&lock_seg)) {
    return ERROR_ENCODING;
  }
  *lock_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  return CKB_SUCCESS;
}

int load_public_key_hash(unsigned char *public_key) {
  int ret;
  uint64_t len = 0;

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != PUBLIC_KEY_SIZE1) {
    return ERROR_WRONG_SCRIPT_ARGS_LEN;
  }
  memcpy(public_key, args_bytes_seg.ptr, args_bytes_seg.size);
  return CKB_SUCCESS;
}

// this method performs RSA signature verification: 1024-bits.
// Given a blake160 format public key hash, this method performs signature
// verifications on input cells using current lock script hash. It then asserts
// that the derive public key hash from the signature matches the given public
// key hash.
// Note that this method is exposed for dynamic linking usage, so the
// "current lock script" mentioned above, does not have to be this current
// script code. It could be a different script code using this script via as a
// library.
__attribute__((visibility("default"))) int validate_rsa_sighash_all(
    uint8_t *output_public_key_hash) {
  int ret = ERROR_RSA_ONLY_INIT;
  unsigned char first_witness[TEMP_SIZE];
  uint64_t len = 0;

  // Load witness of first input
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(first_witness, &witness_len, 0, 0,
                         CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // load signature
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(first_witness, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  uint32_t key_size = ((RsaInfo *)lock_bytes_seg.ptr)->key_size;
  uint32_t info_len = calculate_rsa_info_length(key_size);
  if (lock_bytes_seg.size != info_len) {
    return ERROR_ARGUMENTS_LEN;
  }
  // RSA signature size is different than secp256k1
  // secp256k1 use 65 bytes as signature but RSA actually has dynamic size
  // depending on key size.
  unsigned char rsa_info[info_len];
  memcpy(rsa_info, lock_bytes_seg.ptr, lock_bytes_seg.size);

  // Load tx hash
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  // Prepare sign message
  // message = hash(tx_hash + first_witness_len + first_witness +
  // other_witness(with length))
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  // Clear lock field to zero. Note, the molecule header (4 byte with content
  // SIGNATURE_SIZE) is not cleared. That means, SIGNATURE_SIZE should be always
  // the same value.
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  // digest the first witness
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(witness_len));
  blake2b_update(&blake2b_ctx, first_witness, witness_len);

  // Digest same group witnesses
  size_t i = 1;
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    i += 1;
  }
  // Digest witnesses that not covered by inputs
  i = ckb_calculate_inputs_len();
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    i += 1;
  }
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  size_t pub_key_hash_size = BLAKE160_SIZE;
  int result = validate_signature(NULL, (const uint8_t *)rsa_info, info_len,
                                  (const uint8_t *)message, BLAKE2B_BLOCK_SIZE,
                                  output_public_key_hash, &pub_key_hash_size);
  if (result == 0) {
    mbedtls_printf("validate signature passed\n");
  } else {
    mbedtls_printf("validate signature failed: %d\n", result);
    return ERROR_RSA_VERIFY_FAILED;
  }
  return CKB_SUCCESS;
}
