/*
 * A simple HTLC script designed to be compatible with liquality.io
 */
#define __SHARED_LIBRARY__ 1
#include "blake2b.h"
#include "ckb_syscalls.h"
#include "secp256k1_helper.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define RECID_INDEX 64
#define SIGNATURE_SIZE 65
#define TEMP_SIZE 32768

#define ERROR_SYSCALL -50
#define ERROR_SECP_RECOVER_PUBKEY -51
#define ERROR_SECP_PARSE_SIGNATURE -52
#define ERROR_SECP_SERIALIZE_PUBKEY -53
#define ERROR_PUBKEY_BLAKE160_HASH -54

__attribute__((visibility("default"))) int
validate_secp256k1_blake2b_sighash_all(const uint8_t *pubkey_hash,
                                       const uint8_t *compact_signature,
                                       const uint8_t *first_witness_data,
                                       size_t first_witness_length) {
  uint8_t tx_hash[BLAKE2B_BLOCK_SIZE];
  uint64_t len = BLAKE2B_BLOCK_SIZE;
  int ret = ckb_checked_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, (char *)&first_witness_length, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, first_witness_data, first_witness_length);

  uint8_t buffer[TEMP_SIZE];
  /* Digest same group witnesses */
  size_t i = 1;
  while (1) {
    len = TEMP_SIZE;
    ret = ckb_checked_load_witness(buffer, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, buffer, len);
    i += 1;
  }
  /* Digest witnesses that not covered by inputs */
  i = ckb_calculate_inputs_len();
  while (1) {
    len = TEMP_SIZE;
    ret = ckb_checked_load_witness(buffer, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, buffer, len);
    i += 1;
  }
  uint8_t message[BLAKE2B_BLOCK_SIZE];
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  /* Load signature */
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, compact_signature,
          compact_signature[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  /* Check pubkey hash */
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, buffer, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, buffer, pubkey_size);
  blake2b_final(&blake2b_ctx, buffer, BLAKE2B_BLOCK_SIZE);

  if (memcmp(pubkey_hash, buffer, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return CKB_SUCCESS;
}
