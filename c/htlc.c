/*
 * A simple HTLC script designed to be compatible with liquality.io
 */
#include "ckb_dlfcn.h"
#include "ckb_syscalls.h"
#include "ckb_utils.h"
#include "protocol.h"
#include "secp256k1_blake2b_sighash_all_lib.h"
#include "sha256.h"

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_VERIFICATION -12
#define ERROR_SECP_PARSE_PUBKEY -13
#define ERROR_SECP_PARSE_SIGNATURE -14
#define ERROR_SECP_SERIALIZE_PUBKEY -15
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_WITNESS_SIZE -22
#define ERROR_PUBKEY_BLAKE160_HASH -31
#define ERROR_SECRET_HASH -101
#define ERROR_INCORRECT_SINCE -102
#define ERROR_DYNAMIC_LOADING -103

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

#define SCRIPT_ARG_SIZE (BLAKE160_SIZE * 2 + SHA256_BLOCK_SIZE + 8)

/* Extract lock from WitnessArgs */
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
  uint8_t secp_code_buffer[100 * 1024];
  uint64_t pad = RISCV_PGSIZE - ((uint64_t)secp_code_buffer) % RISCV_PGSIZE;
  uint8_t *aligned_code_start = secp_code_buffer + pad;
  size_t aligned_size = ROUNDDOWN(100 * 1024 - pad, RISCV_PGSIZE);

  void *handle = NULL;
  uint64_t consumed_size = 0;
  int ret =
      ckb_dlopen(secp256k1_blake2b_sighash_all_data_hash, aligned_code_start,
                 aligned_size, &handle, &consumed_size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  int (*verify_func)(const uint8_t *, const uint8_t *, const uint8_t *, size_t);
  *(void **)(&verify_func) =
      ckb_dlsym(handle, "validate_secp256k1_blake2b_sighash_all");
  if (verify_func == NULL) {
    return ERROR_DYNAMIC_LOADING;
  }

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
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
  unsigned char witness[MAX_WITNESS_SIZE];
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(witness, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  uint64_t lock_bytes_len = lock_bytes_seg.size;
  if (lock_bytes_len < SIGNATURE_SIZE || lock_bytes_len > MAX_WITNESS_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  unsigned char lock_bytes[MAX_WITNESS_SIZE];
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_len);

  /* Clear lock field to zero for the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_len);

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
    ret = verify_func(&args_bytes_seg.ptr[BLAKE160_SIZE], lock_bytes, witness,
                      witness_len);
    if (ret != CKB_SUCCESS) {
      return ret;
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
    if (ckb_epoch_number_with_fraction_cmp(since, input_since) > 0) {
      return ERROR_INCORRECT_SINCE;
    }
    ret = verify_func(args_bytes_seg.ptr, lock_bytes, witness, witness_len);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }
  return CKB_SUCCESS;
}
