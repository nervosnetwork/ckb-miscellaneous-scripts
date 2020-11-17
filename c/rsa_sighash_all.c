// # rsa_sighash_all
// same as secp256k1_blake2b_sighash_all_dual but with RSA (mbedtls)
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>
#ifndef ASSERT
#define ASSERT(s) (void)0
#endif

#include "rsa_sighash_all.h"

#include <string.h>

#include "blake2b.h"
#include "mbedtls/ecdsa.h"
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
#define ERROR_RSA_INVALID_ID (-47)
#define ERROR_D1_INVALID_ARG1 (-51)
#define ERROR_D1_INVALID_ARG2 (-52)
#define ERROR_D1_INVALID_ARG3 (-53)
#define ERROR_D1_INVALID_ARG4 (-54)
#define ERROR_D1_INVALID_ARG5 (-55)
#define ERROR_D1_INVALID_ARG6 (-56)
#define ERROR_D1_INVALID_ARG7 (-57)
#define ERROR_D1_INVALID_TSUM (-58)
#define ERROR_D1_NOT_SIX (-59)

#define RSA_VALID_KEY_SIZE1 1024
#define RSA_VALID_KEY_SIZE2 2048
#define RSA_VALID_KEY_SIZE3 4096

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20

#define PUBLIC_KEY_SIZE1 (RSA_VALID_KEY_SIZE1 / 8 + 4)
#define PUBLIC_KEY_SIZE2 (RSA_VALID_KEY_SIZE2 / 8 + 4)
#define PUBLIC_KEY_SIZE3 (RSA_VALID_KEY_SIZE3 / 8 + 4)

#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#define CHECK(code)  \
  do {               \
    if (code != 0) { \
      err = code;    \
      ASSERT(0);     \
      goto exit;     \
    }                \
  } while (0)

#if defined(CKB_USE_SIM)
#include <stdio.h>
#define mbedtls_printf printf
#else
#define mbedtls_printf(x, ...) (void)0
#endif

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
                          size_t *olen) {
  return 0;
}
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

uint32_t calculate_rsa_info_length(int key_size) { return 12 + key_size / 4; }

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
int validate_signature_rsa(void *prefilled_data,
                           const uint8_t *signature_buffer,
                           size_t signature_size, const uint8_t *hash_buff,
                           size_t hash_size, uint8_t *output,
                           size_t *output_len) {
  (void)prefilled_data;
  int ret;
  int err = ERROR_RSA_ONLY_INIT;
  mbedtls_rsa_context rsa;
  RsaInfo *input_info = (RsaInfo *)signature_buffer;

  // for key size with 1024 and 2048 bits, it uses up to 7K bytes.
  int alloc_buff_size = 1024 * 7;
  // for key size with 4096 bits, it uses 12K bytes at most.
  if (input_info->key_size > 2048) alloc_buff_size = 1024 * 12;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  CHECK2(input_info->key_size == RSA_VALID_KEY_SIZE1 ||
             input_info->key_size == RSA_VALID_KEY_SIZE2 ||
             input_info->key_size == RSA_VALID_KEY_SIZE3,
         ERROR_RSA_INVALID_KEY_SIZE);
  CHECK2(signature_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK2(hash_buff != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK2(
      signature_size == (size_t)calculate_rsa_info_length(input_info->key_size),
      ERROR_RSA_INVALID_PARAM2);
  CHECK2(*output_len >= BLAKE160_SIZE, ERROR_RSA_INVALID_BLADE2B_SIZE);

  mbedtls_mpi_read_binary_le(&rsa.E, (const unsigned char *)&input_info->E,
                             sizeof(uint32_t));
  mbedtls_mpi_read_binary_le(&rsa.N, input_info->N, input_info->key_size / 8);
  rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

  ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                 MBEDTLS_MD_NONE, hash_size, hash_buff,
                                 get_rsa_signature(input_info));
  if (ret != 0) {
    mbedtls_printf("mbedtls_rsa_pkcs1_verify returned -0x%0x\n",
                   (unsigned int)-ret);
    err = ERROR_RSA_VERIFY_FAILED;
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

  err = CKB_SUCCESS;

exit:
  if (err != CKB_SUCCESS) {
    mbedtls_printf("validate_signature_rsa() failed.\n");
  }
  mbedtls_rsa_free(&rsa);
  return err;
}

int serialize_secp256r1info(const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                            mbedtls_mpi *s, Secp256r1Info *info) {
  int err = 0;

  err = mbedtls_mpi_write_binary_le(&Q->X, info->public_key,
                                    SECP256R1_PUBLIC_KEY_SIZE / 2);
  CHECK(err);
  err = mbedtls_mpi_write_binary_le(
      &Q->Y, info->public_key + SECP256R1_PUBLIC_KEY_SIZE / 2,
      SECP256R1_PUBLIC_KEY_SIZE / 2);
  CHECK(err);

  err = mbedtls_mpi_write_binary_le(r, info->sig, SECP256R1_SIG_SIZE / 2);
  CHECK(err);
  err = mbedtls_mpi_write_binary_le(s, info->sig + SECP256R1_SIG_SIZE / 2,
                                    SECP256R1_SIG_SIZE / 2);
  CHECK(err);

  err = CKB_SUCCESS;

exit:
  return err;
}

int deserialize_secp256r1info(mbedtls_ecp_point *Q, mbedtls_mpi *r,
                              mbedtls_mpi *s, const Secp256r1Info *info) {
  int err = 0;
  mbedtls_ecp_point_init(Q);
  mbedtls_mpi_init(r);
  mbedtls_mpi_init(s);

  err = mbedtls_mpi_read_binary_le(&Q->X, info->public_key,
                                   SECP256R1_PUBLIC_KEY_SIZE / 2);
  CHECK(err);
  err = mbedtls_mpi_read_binary_le(
      &Q->Y, info->public_key + SECP256R1_PUBLIC_KEY_SIZE / 2,
      SECP256R1_PUBLIC_KEY_SIZE / 2);
  CHECK(err);

  const uint32_t one = 1;
  err = mbedtls_mpi_read_binary_le(&Q->Z, (const unsigned char *)&one, 4);
  CHECK(err);

  err = mbedtls_mpi_read_binary_le(r, info->sig, SECP256R1_SIG_SIZE / 2);
  CHECK(err);
  err = mbedtls_mpi_read_binary_le(s, info->sig + SECP256R1_SIG_SIZE / 2,
                                   SECP256R1_SIG_SIZE / 2);
  CHECK(err);

  err = CKB_SUCCESS;
exit:
  return err;
}

int validate_signature_secp256r1(void *prefilled_data,
                                 const uint8_t *signature_buffer,
                                 size_t signature_size,
                                 const uint8_t *hash_buff, size_t hash_size,
                                 uint8_t *output, size_t *output_len) {
  (void)prefilled_data;
  (void)output;
  (void)output_len;
  int err = 0;
  int id = MBEDTLS_ECP_DP_SECP256R1;
  mbedtls_ecp_group grp;
  int alloc_buff_size = 700 * 1024;

  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  const Secp256r1Info *info = (Secp256r1Info *)signature_buffer;
  CHECK2(signature_size == sizeof(Secp256r1Info), ERROR_RSA_INVALID_PARAM1);
  CHECK2(hash_size == 32, ERROR_RSA_INVALID_PARAM1);

  mbedtls_ecp_group_init(&grp);
  err = mbedtls_ecp_group_load(&grp, id);
  CHECK(err);

  mbedtls_ecp_point Q;
  mbedtls_mpi r;
  mbedtls_mpi s;
  err = deserialize_secp256r1info(&Q, &r, &s, info);
  CHECK(err);

  err = mbedtls_ecdsa_verify(&grp, hash_buff, hash_size, &Q, &r, &s);
  CHECK(err);

  err = CKB_SUCCESS;
exit:
  return err;
}

/**
 * entry for different algorithms
 * The fist byte of signature_buffer is the id of algorithm, it can be:
 * #define CKB_VERIFY_RSA 1
 * #define CKB_VERIFY_SECP256R1 2
 */
__attribute__((visibility("default"))) int validate_signature(
    void *prefilled_data, const uint8_t *signature_buffer,
    size_t signature_size, const uint8_t *hash_buff, size_t hash_size,
    uint8_t *output, size_t *output_len) {
  if (signature_buffer == NULL) {
    ASSERT(0);
    return ERROR_RSA_INVALID_PARAM1;
  }
  uint32_t id = ((RsaInfo *)signature_buffer)->algorithm_id;

  if (id == CKB_VERIFY_RSA) {
    return validate_signature_rsa(prefilled_data, signature_buffer,
                                  signature_size, hash_buff, hash_size, output,
                                  output_len);
  } else if (id == CKB_VERIFY_SECP256R1) {
    return validate_signature_secp256r1(prefilled_data, signature_buffer,
                                        signature_size, hash_buff, hash_size,
                                        output, output_len);
  } else {
    return ERROR_RSA_INVALID_ID;
  }
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

// this method performs RSA signature verification: it supports variable key
// sizes: 1024, 2048 and 4096.
//
// Given a blake160 format public key hash, this
// method performs signature verifications on input cells using current lock
// script hash. It then asserts that the derive public key hash from the
// signature matches the given public key hash.
//
// Note that this method is exposed
// for dynamic linking usage, so the "current lock script" mentioned above, does
// not have to be this current script code. It could be a different script code
// using this script via as a library.
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

// ISO 9796-1 padding scheme
typedef struct ISO9796D1Encoding {
  int32_t bit_size;  // same as key size, 512, 1024, 2048, etc.
  int32_t pad_bits;  // always set it to 4
} ISO9796D1Encoding;

uint32_t d1_cal_block_length(ISO9796D1Encoding* enc);
int d1_encode(ISO9796D1Encoding* enc, uint8_t in[], uint32_t in_off,
              uint32_t in_len, uint8_t block[], uint32_t block_length,
              uint32_t* real_block_length);
int d1_decode(ISO9796D1Encoding* enc, uint8_t block[], uint32_t block_length,
              uint8_t new_block[], uint32_t* new_block_length);

static uint8_t s_shadows[] = {0xe, 0x3, 0x5, 0x8, 0x9, 0x4, 0x2, 0xf,
                              0x0, 0xd, 0xb, 0x6, 0x7, 0xa, 0xc, 0x1};
static uint8_t s_inverse[] = {0x8, 0xf, 0x6, 0x1, 0x5, 0x2, 0xb, 0xc,
                              0x3, 0x4, 0xd, 0xa, 0xe, 0x9, 0x0, 0x7};

uint32_t d1_cal_block_length(ISO9796D1Encoding *enc) {
  return (enc->bit_size + 7) / 8;
}

int d1_encode(ISO9796D1Encoding *enc, uint8_t in[], uint32_t in_off,
              uint32_t in_len, uint8_t block[], uint32_t block_length,
              uint32_t *real_block_length) {
  int err = 0;
  CHECK2(enc != NULL, ERROR_D1_INVALID_ARG1);
  CHECK2(block != NULL, ERROR_D1_INVALID_ARG1);
  CHECK2(in_off < in_len, ERROR_D1_INVALID_ARG1);
  CHECK2(block_length > 0, ERROR_D1_INVALID_ARG1);
  CHECK2(real_block_length != NULL, ERROR_D1_INVALID_ARG1);

  uint32_t r = enc->pad_bits + 1;
  uint32_t z = in_len;
  uint32_t t = (enc->bit_size + 13) / 16;

  for (uint32_t i = 0; i < t; i += z) {
    if (i > (t - z)) {
      memcpy(block + block_length - t, in + in_off + in_len - (t - i), t - i);
    } else {
      memcpy(block + block_length - (i + z), in + in_off, z);
    }
  }
  CHECK2(block_length >= 2 * t, ERROR_D1_INVALID_ARG3);
  for (uint32_t i = block_length - 2 * t; i != block_length; i += 2) {
    uint8_t val = block[block_length - t + i / 2];
    block[i] =
        (uint8_t)((s_shadows[(val & 0xff) >> 4] << 4) | s_shadows[val & 0x0f]);
    block[i + 1] = val;
  }

  CHECK2(block_length >= 2 * z, ERROR_D1_INVALID_ARG3);
  block[block_length - 2 * z] ^= r;
  block[block_length - 1] = (uint8_t)((block[block_length - 1] << 4) | 0x06);

  int maxBit = (8 - (enc->bit_size - 1) % 8);
  int offset = 0;

  if (maxBit != 8) {
    block[0] &= (0xff >> maxBit);
    block[0] |= (0x80 >> maxBit);
  } else {
    block[0] = 0x00;
    block[1] |= 0x80;
    offset = 1;
  }
  if (offset == 1) {
    memmove(block, block + 1, block_length - 1);
    *real_block_length = block_length - 1;
  } else {
    *real_block_length = block_length;
  }

  err = 0;
exit:
  return err;
}

int d1_decode(ISO9796D1Encoding *enc, uint8_t block[], uint32_t block_length,
              uint8_t new_block[], uint32_t *new_block_length) {
  int err = 0;
  CHECK2(block != NULL, ERROR_D1_INVALID_ARG2);
  CHECK2(new_block != NULL, ERROR_D1_INVALID_ARG2);
  CHECK2(new_block_length != NULL && *new_block_length == block_length,
         ERROR_D1_INVALID_ARG2);

  uint32_t r = 1;
  uint32_t t = (enc->bit_size + 13) / 16;

  int8_t *ptr = (int8_t *)block;
  if (block[0] == 0) {
    memmove(block, block + 1, block_length - 1);
    block_length -= 1;
    mbedtls_printf("block[0] == 0, shrinked\n");
  }
  CHECK2((block[block_length - 1] & 0x0f) == 0x6, ERROR_D1_NOT_SIX);

  block[block_length - 1] =
      (uint8_t)(((block[block_length - 1] & 0xff) >> 4) |
                ((s_inverse[(block[block_length - 2] & 0xff) >> 4]) << 4));

  block[0] = (uint8_t)((s_shadows[(block[1] & 0xff) >> 4] << 4) |
                       s_shadows[block[1] & 0x0f]);
  bool boundaryFound = false;
  int boundary = 0;

  ASSERT(block_length >= 2 * t);
  int lower_bound = (int)(block_length - 2 * t);
  for (int i = block_length - 1; i >= lower_bound; i -= 2) {
    int val =
        ((s_shadows[(block[i] & 0xff) >> 4] << 4) | s_shadows[block[i] & 0x0f]);
    if (((block[i - 1] ^ val) & 0xff) != 0) {
      if (!boundaryFound) {
        boundaryFound = true;
        r = (block[i - 1] ^ val) & 0xff;
        boundary = i - 1;
      } else {
        err = ERROR_D1_INVALID_TSUM;
        goto exit;
      }
    }
  }
  block[boundary] = 0;

  *new_block_length = (block_length - boundary) / 2;

  for (uint32_t i = 0; i < *new_block_length; i++) {
    new_block[i] = block[2 * i + boundary + 1];
  }
  enc->pad_bits = r - 1;

  err = 0;
exit:
  return err;
}
