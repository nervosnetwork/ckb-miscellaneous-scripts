/*
 * A simple UDT script using 128 bit unsigned integer range
 *
 * This UDT has 2 unlocking modes:
 *
 * 1. If one of the transaction input has a lock script matching the UDT
 * script argument, the UDT script will be in owner mode. In owner mode no
 * checks is performed, the owner can perform any operations such as issuing
 * more UDTs or burning UDTs. By ensuring at least one transaction input has
 * a matching lock script, the ownership of UDT can be ensured.
 * 2. Otherwise, the UDT script will be in normal mode, where it ensures the
 * sum of all input tokens is the same as the sum of all output tokens.
 *
 * Notice one caveat of this UDT script is that only one UDT can be issued
 * for each unique lock script. A more sophisticated UDT script might include
 * other arguments(such as the hash of the first input) as a unique identifier,
 * however for the sake of simplicity, we are happy with this limitation.
 */
#include "blockchain.h"
#include "ckb_syscalls.h"

#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_SIZE 32768

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_OVERFLOWING -51
#define ERROR_AMOUNT -52

typedef unsigned __int128 uint128_t;

int main() {
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
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
  if (args_bytes_seg.size != BLAKE2B_BLOCK_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  int owner_mode = 0;
  size_t i = 0;
  while (1) {
    uint8_t buffer[BLAKE2B_BLOCK_SIZE];
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_INPUT,
                                         CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
    if (memcmp(buffer, args_bytes_seg.ptr, BLAKE2B_BLOCK_SIZE) == 0) {
      owner_mode = 1;
      break;
    }
    i += 1;
  }

  if (owner_mode) {
    return CKB_SUCCESS;
  }

  uint128_t input_amount = 0;
  i = 0;
  while (1) {
    uint128_t current_amount = 0;
    len = 16;
    ret = ckb_load_cell_data((uint8_t *)&current_amount, &len, 0, i,
                             CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 16) {
      return ERROR_ENCODING;
    }
    input_amount += current_amount;
    if (input_amount < current_amount) {
      return ERROR_OVERFLOWING;
    }
    i += 1;
  }

  uint128_t output_amount = 0;
  i = 0;
  while (1) {
    uint128_t current_amount = 0;
    len = 16;
    ret = ckb_load_cell_data((uint8_t *)&current_amount, &len, 0, i,
                             CKB_SOURCE_GROUP_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 16) {
      return ERROR_ENCODING;
    }
    output_amount += current_amount;
    if (output_amount < current_amount) {
      return ERROR_OVERFLOWING;
    }
    i += 1;
  }

  if (input_amount != output_amount) {
    return ERROR_AMOUNT;
  }
  return CKB_SUCCESS;
}
