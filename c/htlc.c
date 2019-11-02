/*
 * A simple HTLC script designed to be compatible with liquality.io
 */
#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "secp256k1_helper.h"
#include "sha256.h"

#define ERROR_SECRET_HASH -101
#define ERROR_INCORRECT_SINCE -102

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

#define SCRIPT_ARG_SIZE (BLAKE160_SIZE * 2 + SHA256_BLOCK_SIZE + 8)

/*
 * Arguments:
 * two 20-byte pubkey blake160 hashes, one 32-byte secret hash, as well as
 * one 8-byte lock time.
 *
 * Witness:
 * WitnessArgs with the following items in lock field:
 * * 65 byte recoverable signature
 * * Optional data use to generate secret hash
 */
int main() {
  int ret;
  uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[TEMP_SIZE];

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
  if (args_bytes_seg.size != SCRIPT_ARG_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  uint64_t lock_bytes_len = lock_bytes_seg.size;
  if (lock_bytes_len < SIGNATURE_SIZE || lock_bytes_len > TEMP_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_len);

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_len);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, witness_len);

  /* Digest same group witnesses */
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  /* Digest witnesses that not covered by inputs */
  i = calculate_inputs_len();
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
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
          &context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  /* Check pubkey hash */
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, temp, pubkey_size);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  if (lock_bytes_len > SIGNATURE_SIZE) {
    unsigned char secret_hash[SHA256_BLOCK_SIZE];
    SHA256_CTX sha256_ctx;
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, &lock_bytes[SIGNATURE_SIZE],
                  lock_bytes_len - SIGNATURE_SIZE);
    sha256_final(&sha256_ctx, secret_hash);
    if (memcmp(&args_bytes_seg.ptr[BLAKE160_SIZE * 2], secret_hash,
               SHA256_BLOCK_SIZE) != 0) {
      return ERROR_SECRET_HASH;
    }
    if (memcmp(&args_bytes_seg.ptr[BLAKE160_SIZE], temp, BLAKE160_SIZE) != 0) {
      return ERROR_PUBKEY_BLAKE160_HASH;
    }
  } else {
    uint64_t since =
        *((uint64_t *)(&args_bytes_seg
                            .ptr[BLAKE160_SIZE * 2 + SHA256_BLOCK_SIZE]));
    uint64_t input_since = 0;
    len = 8;
    ret =
        ckb_load_input_by_field(&input_since, &len, 0, 0,
                                CKB_SOURCE_GROUP_INPUT, CKB_INPUT_FIELD_SINCE);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 8) {
      return ERROR_SYSCALL;
    }
    if (since != input_since) {
      return ERROR_INCORRECT_SINCE;
    }
    if (memcmp(args_bytes_seg.ptr, temp, BLAKE160_SIZE) != 0) {
      return ERROR_PUBKEY_BLAKE160_HASH;
    }
  }

  return 0;
}
