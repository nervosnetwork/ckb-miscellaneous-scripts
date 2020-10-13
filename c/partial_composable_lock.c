// # Partial Composable Lock
//
// A lock used to implement partial transaction design in CKB. Partial
// transaction is a data structure that only contains some inputs, outputs and
// witnesses in CKB. While partial transactions could be slighly expanded into
// a full CKB transaction, they are more designed to compose with each other,
// where multiple partial transactions can be combined into a single CKB
// transaction.
// Note partial transactions are similar to open transactions, however partial
// transactions are designed to workaround one specific quirk in open
// transactions: fixed indices must be given for open transactions, where
// partial transactions only require you specific the number of inputs and
// outputs signed. As long as the inputs(outputs) in one partial transaction
// are assembled consecutively, each partial transaction can be moved freely
// within a CKB transaction, without needing a new signature.
#include "blake2b.h"
#include "blockchain.h"
#include "ckb_streaming.h"
#include "ckb_swappable_signatures.h"
#include "ckb_syscalls.h"
#include "ckb_utils.h"

#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_BUFFER_SIZE 128
#define SIGNATURE_BUFFER_SIZE 1024
#define SIGNATURE_WITNESS_BUFFER_SIZE 32768
#define CODE_SIZE (256 * 1024)
#define PREFILLED_DATA_SIZE (1024 * 1024)
#define IDENTITY_BUFFER_SIZE 1024

#define ERROR_TRANSACTION -1

#ifdef ENABLE_DEBUG_MODE
#define DEBUG(s) ckb_debug(s)
#else
#define DEBUG(s)
#endif /* ENABLE_DEBUG_MODE */

int main() {
  uint8_t current_script_hash[32];
  uint64_t len = 32;
  int ret = ckb_checked_load_script_hash(current_script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 32) {
    return ERROR_TRANSACTION;
  }

  uint8_t script[SCRIPT_BUFFER_SIZE];
  len = SCRIPT_BUFFER_SIZE;
  ret = ckb_checked_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    DEBUG("molecule verification failure!");
    return ERROR_TRANSACTION;
  }
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size <= 33) {
    DEBUG("Script args must be more than 33 bytes long!");
    return ERROR_TRANSACTION;
  }
  const uint8_t *current_identity = &args_bytes_seg.ptr[33];
  size_t identity_size = args_bytes_seg.size - 33;
  if (identity_size > IDENTITY_BUFFER_SIZE) {
    DEBUG("Identity is too large!");
    return ERROR_TRANSACTION;
  }

  uint8_t code_buffer[CODE_SIZE] __attribute__((aligned(RISCV_PGSIZE)));
  uint8_t prefilled_data_buffer[PREFILLED_DATA_SIZE];
  CkbSwappableSignatureInstance instance;
  instance.code_buffer = code_buffer;
  instance.code_buffer_size = CODE_SIZE;
  instance.prefilled_data_buffer = prefilled_data_buffer;
  instance.prefilled_buffer_size = PREFILLED_DATA_SIZE;
  instance.verify_func = NULL;

  ret = ckb_initialize_swappable_signature(args_bytes_seg.ptr,
                                           args_bytes_seg.ptr[32], &instance);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  size_t input_i = 0, output_i = 0;
  uint8_t witness[SIGNATURE_WITNESS_BUFFER_SIZE];
  len = SIGNATURE_WITNESS_BUFFER_SIZE;
  // Initial witness load
  ret = ckb_load_witness(witness, &len, 0, input_i, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  size_t readed_len = len;
  if (readed_len > SIGNATURE_WITNESS_BUFFER_SIZE) {
    readed_len = SIGNATURE_WITNESS_BUFFER_SIZE;
  }

  // Loop through each partial transaction
  int has_more = 1;
  while (has_more) {
    // The first witness in each partial transaction must contain a valid
    // signature.
    size_t start_input_index = input_i;
    uint8_t signature[SIGNATURE_BUFFER_SIZE];
    size_t signature_length;
    uint8_t output_count;

    if (readed_len < 20) {
      DEBUG("Invalid signature witness length!");
      return ERROR_TRANSACTION;
    }
    uint32_t lock_length = *((uint32_t *)(&witness[16]));
    if (readed_len < 20 + lock_length) {
      DEBUG("Witness lock part is far tooooo long!");
      return ERROR_TRANSACTION;
    }
    if (lock_length <= 1) {
      DEBUG("Signature is required!");
      return ERROR_TRANSACTION;
    }
    if (lock_length - 1 > SIGNATURE_BUFFER_SIZE) {
      DEBUG("Signature is too long!");
      return ERROR_TRANSACTION;
    }
    uint8_t *lock = &witness[20];
    output_count = lock[0];
    signature_length = lock_length - 1;
    memcpy(signature, &lock[1], signature_length);
    memset(&lock[1], 0, signature_length);

    blake2b_state message_ctx;
    blake2b_init(&message_ctx, BLAKE2B_BLOCK_SIZE);
    // Hash the first witness
    blake2b_update(&message_ctx, witness, readed_len);
    if (readed_len < len) {
      ret = ckb_load_and_hash(&message_ctx, readed_len, input_i,
                              CKB_SOURCE_GROUP_INPUT, ckb_load_witness);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }

    // Check witnesses for inputs in the same script group, if a new signature
    // is found, a new partial transaction is encountered.
    while (1) {
      input_i++;
      len = SIGNATURE_WITNESS_BUFFER_SIZE;
      ret = ckb_load_witness(witness, &len, 0, input_i, CKB_SOURCE_GROUP_INPUT);
      if (ret == CKB_INDEX_OUT_OF_BOUND) {
        has_more = 0;
        break;
      }
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      readed_len = len;
      if (readed_len > SIGNATURE_WITNESS_BUFFER_SIZE) {
        readed_len = SIGNATURE_WITNESS_BUFFER_SIZE;
      }

      if (readed_len != 0 && readed_len < 20) {
        DEBUG("Invalid witness length!");
        return ERROR_TRANSACTION;
      }
      if (readed_len != 0) {
        uint32_t lock_length = *((uint32_t *)(&witness[16]));
        if (lock_length > 0) {
          // A new partial transaction is encountered
          break;
        }
      }
      // Hash witness for the current partial transaction
      blake2b_update(&message_ctx, witness, readed_len);
      if (readed_len < len) {
        ret = ckb_load_and_hash(&message_ctx, readed_len, input_i,
                                CKB_SOURCE_GROUP_INPUT, ckb_load_witness);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
      }
    }

    // Now hash all the inputs belonging to current transaction
    for (size_t j = start_input_index; j < input_i; j++) {
      ret = ckb_hash_input(&message_ctx, j, CKB_SOURCE_GROUP_INPUT);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
    if (output_count > 0) {
      // Locate the first output for current partial transaction
      while (1) {
        uint8_t lock_hash[32];
        len = 32;
        ret =
            ckb_load_cell_by_field(lock_hash, &len, 0, output_i,
                                   CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (len != 32) {
          return ERROR_TRANSACTION;
        }
        if (memcmp(lock_hash, current_script_hash, 32) == 0) {
          break;
        }
        output_i++;
      }
      // Hash all the outputs(with data) belonging to current transaction
      for (uint32_t j = 0; j < output_count; j++) {
        ret = ckb_hash_cell(&message_ctx, output_i, CKB_SOURCE_OUTPUT);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        uint8_t hash[32];
        len = 32;
        ckb_load_cell_by_field(hash, &len, 0, output_i, CKB_SOURCE_OUTPUT,
                               CKB_CELL_FIELD_DATA_HASH);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (len != 32) {
          return ERROR_TRANSACTION;
        }
        blake2b_update(&message_ctx, hash, 32);
        output_i++;
      }
    }
    // Signature verification
    uint8_t message[BLAKE2B_BLOCK_SIZE];
    blake2b_final(&message_ctx, message, BLAKE2B_BLOCK_SIZE);
    uint8_t verified_identity[IDENTITY_BUFFER_SIZE];
    size_t verified_identity_length = IDENTITY_BUFFER_SIZE;
    ret = instance.verify_func(instance.prefilled_data_buffer, signature,
                               signature_length, message, BLAKE2B_BLOCK_SIZE,
                               verified_identity, &verified_identity_length);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if ((verified_identity_length != identity_size) ||
        (memcmp(verified_identity, current_identity, identity_size) != 0)) {
      DEBUG("Invalid identity!");
      return ERROR_TRANSACTION;
    }
  }
  return CKB_SUCCESS;
}
