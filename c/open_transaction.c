// # Open Transaction
//
// An open transaction implementation. Right now it is tied to
// secp256k1-blake160 signature verification algorithm. Later we might
// change it for more use cases.
#include "blake2b.h"
#include "blockchain.h"
#include "ckb_syscalls.h"
#include "ckb_utils.h"
#include "secp256k1_helper.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define RECID_INDEX 64
#define SIGNATURE_SIZE 65
/* 32 KB */
#define WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define ONE_BATCH_SIZE 4096

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
#define ERROR_INVALID_PREFILLED_DATA_SIZE -41
#define ERROR_INVALID_SIGNATURE_SIZE -42
#define ERROR_INVALID_MESSAGE_SIZE -43
#define ERROR_INVALID_OUTPUT_SIZE -44
#define ERROR_INVALID_LABEL -50
#define ERROR_INVALID_MASK -51

#define LABEL_SIGHASH_ALL 0x0
#define LABEL_END_OF_LIST 0xF
#define LABEL_OUTPUT 0x1
#define LABEL_INPUT_CELL 0x2
#define LABEL_INPUT_CELL_SINCE 0x3
#define LABEL_INPUT_OUTPOINT 0x4

#define MASK_CELL_CAPACITY 0x0
#define MASK_CELL_TYPE_CODE_HASH 0x1
#define MASK_CELL_TYPE_ARGS 0x2
#define MASK_CELL_TYPE_HASH_TYPE 0x3
#define MASK_CELL_LOCK_CODE_HASH 0x4
#define MASK_CELL_LOCK_ARGS 0x5
#define MASK_CELL_LOCK_HASH_TYPE 0x6
#define MASK_CELL_DATA 0x7

#define MASK_OUTPOINT_TX_HASH 0x0
#define MASK_OUTPOINT_INDEX 0x1
#define MASK_OUTPOINT_SINCE 0x2
#define MASK_OUTPOINT_ALL 0x3

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

int main() {
  unsigned char witness[WITNESS_SIZE];
  // Load witness of first input
  uint64_t witness_len = WITNESS_SIZE;
  int ret =
      ckb_load_witness(witness, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (witness_len > WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // Parse and process sighash coverage array
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(witness, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  // Open transaction witness should at least have a signature, and a sighash
  // coverage array that contains at least one item.
  if (lock_bytes_seg.size <= SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  size_t sighash_array_length = lock_bytes_seg.size - SIGNATURE_SIZE;
  if (sighash_array_length % 3 != 0) {
    return ERROR_ARGUMENTS_LEN;
  }

  // Process sighash coverage array
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  uint8_t *sighash_array = (uint8_t *)lock_bytes_seg.ptr;

  for (size_t i = 0; i < sighash_array_length / 3; i++) {
    uint8_t *tx_component = &sighash_array[i * 3];
    uint8_t label = tx_component[0] >> 4;
    uint16_t index_code =
        (((uint16_t)(tx_component[0] & 0xF)) << 8) | tx_component[1];
    uint8_t mask = tx_component[2];

    // The last item must be 0xF, which is end of list.
    if (i == sighash_array_length / 3 - 1) {
      if (label != LABEL_END_OF_LIST) {
        return ERROR_INVALID_LABEL;
      }
    }

    switch (label) {
      case LABEL_SIGHASH_ALL: {
        unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
        uint64_t len = BLAKE2B_BLOCK_SIZE;
        ret = ckb_load_tx_hash(tx_hash, &len, 0);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (len != BLAKE2B_BLOCK_SIZE) {
          return ERROR_SYSCALL;
        }
        blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);
      } break;
      case LABEL_OUTPUT:
      case LABEL_INPUT_CELL:
      case LABEL_INPUT_CELL_SINCE: {
        size_t source =
            (label == LABEL_OUTPUT) ? CKB_SOURCE_OUTPUT : CKB_SOURCE_INPUT;
        size_t field;
        uint8_t item;
        switch (mask) {
          case MASK_CELL_CAPACITY: {
            uint64_t capacity = 0;
            uint64_t len = 8;
            int ret = ckb_load_cell_by_field((uint8_t *)(&capacity), &len, 0,
                                             index_code, source,
                                             CKB_CELL_FIELD_CAPACITY);
            if (ret != CKB_SUCCESS) {
              return ret;
            }
            blake2b_update(&blake2b_ctx, (uint8_t *)(&capacity), 8);
          } break;
          case MASK_CELL_LOCK_CODE_HASH:
          case MASK_CELL_LOCK_ARGS:
          case MASK_CELL_LOCK_HASH_TYPE:
            field = CKB_CELL_FIELD_LOCK;
            item = mask;
            goto PROCESS_SCRIPT;
          case MASK_CELL_TYPE_CODE_HASH:
            field = CKB_CELL_FIELD_TYPE;
            item = MASK_CELL_LOCK_CODE_HASH;
            goto PROCESS_SCRIPT;
          case MASK_CELL_TYPE_ARGS:
            field = CKB_CELL_FIELD_TYPE;
            item = MASK_CELL_LOCK_ARGS;
            goto PROCESS_SCRIPT;
          case MASK_CELL_TYPE_HASH_TYPE:
            field = CKB_CELL_FIELD_TYPE;
            item = MASK_CELL_LOCK_HASH_TYPE;
          PROCESS_SCRIPT : {
            unsigned char script[SCRIPT_SIZE];
            uint64_t len = SCRIPT_SIZE;
            int ret = ckb_checked_load_cell_by_field(script, &len, 0,
                                                     index_code, source, field);
            if (ret != CKB_SUCCESS) {
              return ret;
            }

            mol_seg_t script_seg;
            script_seg.ptr = (uint8_t *)script;
            script_seg.size = len;
            if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
              return ERROR_ENCODING;
            }

            mol_seg_t item_seg;
            switch (item) {
              case MASK_CELL_LOCK_CODE_HASH:
                item_seg = MolReader_Script_get_code_hash(&script_seg);
                blake2b_update(&blake2b_ctx, item_seg.ptr, item_seg.size);
                break;
              case MASK_CELL_LOCK_ARGS:
                item_seg = MolReader_Script_get_args(&script_seg);
                blake2b_update(&blake2b_ctx, item_seg.ptr, item_seg.size);
                break;
              case MASK_CELL_LOCK_HASH_TYPE:
                item_seg = MolReader_Script_get_hash_type(&script_seg);
                blake2b_update(&blake2b_ctx, item_seg.ptr, item_seg.size);
                break;
            }
          } break;
          case MASK_CELL_DATA: {
            uint8_t temp[ONE_BATCH_SIZE];
            uint64_t len = ONE_BATCH_SIZE;
            int ret = ckb_load_cell_data(temp, &len, 0, index_code, source);
            if (ret != CKB_SUCCESS) {
              return ret;
            }
            uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
            blake2b_update(&blake2b_ctx, temp, offset);
            while (offset < len) {
              uint64_t current_len = ONE_BATCH_SIZE;
              ret = ckb_load_cell_data(temp, &current_len, offset, index_code,
                                       source);
              if (ret != CKB_SUCCESS) {
                return ret;
              }
              uint64_t current_read =
                  (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
              blake2b_update(&blake2b_ctx, temp, current_read);
              offset += current_read;
            }
          } break;
          default:
            return ERROR_INVALID_MASK;
        }
        if (label == LABEL_INPUT_CELL_SINCE) {
          uint8_t since[8];
          uint64_t len = 8;
          int ret = ckb_load_input_by_field(since, &len, 0, index_code, source,
                                            CKB_INPUT_FIELD_SINCE);
          if (ret != CKB_SUCCESS) {
            return ret;
          }
          blake2b_update(&blake2b_ctx, since, 8);
        }
      } break;
      case LABEL_INPUT_OUTPOINT: {
        uint8_t buf[512];
        uint64_t len = 512;
        int ret;
        if (mask == MASK_OUTPOINT_ALL) {
          ret = ckb_checked_load_input(buf, &len, 0, index_code,
                                       CKB_SOURCE_INPUT);
        } else {
          switch (mask) {
            case MASK_OUTPOINT_SINCE:
              ret = ckb_checked_load_input_by_field(buf, &len, 0, index_code,
                                                    CKB_SOURCE_INPUT,
                                                    CKB_INPUT_FIELD_SINCE);
              break;
            case MASK_OUTPOINT_TX_HASH:
            case MASK_OUTPOINT_INDEX: {
              uint8_t temp[512];
              uint64_t temp_len = 512;
              ret = ckb_checked_load_input_by_field(
                  temp, &temp_len, 0, index_code, CKB_SOURCE_INPUT,
                  CKB_INPUT_FIELD_OUT_POINT);
              if (ret != CKB_SUCCESS) {
                return ret;
              }
              mol_seg_t outpoint_seg;
              outpoint_seg.ptr = temp;
              outpoint_seg.size = temp_len;
              if (MolReader_OutPoint_verify(&outpoint_seg, false) != MOL_OK) {
                return ERROR_ENCODING;
              }
              if (mask == MASK_OUTPOINT_TX_HASH) {
                mol_seg_t tx_hash_seg =
                    MolReader_OutPoint_get_tx_hash(&outpoint_seg);
                memcpy(buf, tx_hash_seg.ptr, tx_hash_seg.size);
                len = tx_hash_seg.size;
              } else {
                mol_seg_t index_seg =
                    MolReader_OutPoint_get_tx_hash(&index_seg);
                memcpy(buf, index_seg.ptr, index_seg.size);
                len = index_seg.size;
              }
              ret = CKB_SUCCESS;
            } break;
            default:
              return ERROR_INVALID_MASK;
          }
        }
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        blake2b_update(&blake2b_ctx, buf, len);
      } break;
      case LABEL_END_OF_LIST:
        if (i != sighash_array_length / 3 - 1) {
          return ERROR_INVALID_LABEL;
        }
        break;
      default:
        return ERROR_INVALID_LABEL;
    }
  }

  uint8_t signature_bytes[SIGNATURE_SIZE];
  memcpy(signature_bytes, &lock_bytes_seg.ptr[sighash_array_length],
         SIGNATURE_SIZE);
  // Clear lock field to zero, then digest the first witness
  memset((void *)(&lock_bytes_seg.ptr[sighash_array_length]), 0,
         SIGNATURE_SIZE);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, witness, witness_len);

  uint8_t temp[WITNESS_SIZE];
  // Digest same group witnesses
  size_t i = 1;
  while (1) {
    uint64_t len = WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  // Digest witnesses that not covered by inputs
  i = ckb_calculate_inputs_len();
  while (1) {
    uint64_t len = WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  // Load signature
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_load_data(secp_data);
  if (ret != 0) {
    return ret;
  }
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, signature_bytes,
          signature_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  // Recover pubkey
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  // Check pubkey hash
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, temp, pubkey_size);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  // Load args
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
  if (args_bytes_seg.size != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  if (memcmp(args_bytes_seg.ptr, temp, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return 0;
}
