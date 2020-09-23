// # PoA
//
// A lock script used for proof of authority governance on CKB.

// Due to the way CKB works, shared state in dapps is a common problem requiring
// special care. One naive solution, is to introduce a certain kind of
// aggregator, that would pack multiple invididual actions on the sahred state
// into a single CKB transaction. But one issue with aggregator is
// centralization: with one aggregator, the risk of censoring is quite high.
// This script provides a simple attempt at the problem: we will just use
// multiple aggregators! Each aggregator can only issue a new transaction when
// their round is reached. Notice that this is by no means the solution to the
// problem we are facing. Many better attempts are being built, the lock script
// here, simply is built to show one of many possibilities on CKB, and help
// inspire new ideas.

// As always, we will need those headers to interact with CKB.
#include "blake2b.h"
#include "blockchain.h"
#include "ckb_dlfcn.h"
#include "ckb_syscalls.h"

#define BUFFER_SIZE 32768
#define ONE_BATCH_SIZE 32768
#define CODE_SIZE (256 * 1024)
#define PREFILLED_DATA_SIZE (1024 * 1024)
#define IDENTITY_SIZE 1024

#define ERROR_TRANSACTION -1
#define ERROR_ENCODING -2
#define ERROR_DYNAMIC_LOADING -3

#ifdef ENABLE_DEBUG_MODE
#define DEBUG(s) ckb_debug(s)
#else
#define DEBUG(s)
#endif /* ENABLE_DEBUG_MODE */

int load_and_hash_witness(blake2b_state *ctx, size_t start, size_t index,
                          size_t source) {
  uint8_t temp[ONE_BATCH_SIZE];
  uint64_t len = ONE_BATCH_SIZE;
  int ret = ckb_load_witness(temp, &len, start, index, source);
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

int validate_signature(const uint8_t *code_hash, uint8_t hash_type,
                       const uint8_t *signature, size_t signature_size,
                       const uint8_t *identity, size_t identity_size,
                       blake2b_state *message_ctx) {
  // Digest same group witnesses
  size_t i = 1;
  while (1) {
    int ret = load_and_hash_witness(message_ctx, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    i += 1;
  }
  // Digest witnesses that not covered by inputs
  i = ckb_calculate_inputs_len();
  while (1) {
    int ret = load_and_hash_witness(message_ctx, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    i += 1;
  }
  uint8_t message[32];
  blake2b_final(message_ctx, message, 32);

  uint8_t code_buffer[CODE_SIZE] __attribute__((aligned(RISCV_PGSIZE)));
  void *handle = NULL;
  uint64_t consumed_size = 0;
  int ret = ckb_dlopen2(code_hash, hash_type, code_buffer, CODE_SIZE, &handle,
                        &consumed_size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  int (*load_prefilled_data_func)(void *, size_t *);
  *(void **)(&load_prefilled_data_func) =
      ckb_dlsym(handle, "load_prefilled_data");
  if (load_prefilled_data_func == NULL) {
    DEBUG("Error loading load prefilled data func!");
    return ERROR_DYNAMIC_LOADING;
  }
  int (*verify_func)(void *, const uint8_t *, size_t, const uint8_t *, size_t,
                     uint8_t *, size_t *);
  *(void **)(&verify_func) = ckb_dlsym(handle, "validate_signature");
  if (verify_func == NULL) {
    DEBUG("Error loading validate signature func!");
    return ERROR_DYNAMIC_LOADING;
  }
  uint8_t prefilled_data_buffer[PREFILLED_DATA_SIZE];
  uint64_t len = PREFILLED_DATA_SIZE;
  ret = load_prefilled_data_func(prefilled_data_buffer, &len);
  if (ret != CKB_SUCCESS) {
    DEBUG("Error loading prefilled data!");
    return ret;
  }
  uint8_t output_identity[IDENTITY_SIZE];
  len = IDENTITY_SIZE;
  ret = verify_func(prefilled_data_buffer, signature, signature_size, message,
                    32, output_identity, &len);
  if (ret != CKB_SUCCESS) {
    DEBUG("Error validating signature");
    return ret;
  }
  if (len != identity_size) {
    DEBUG("Identity size does not match!");
    return ERROR_ENCODING;
  }
  if (memcmp(output_identity, identity, identity_size) != 0) {
    DEBUG("Identities do not match!");
    return ERROR_ENCODING;
  }
  return CKB_SUCCESS;
}

int main() {
  // TODO: cell termination.
  // One CKB transaction can only have one cell using current lock.
  uint64_t len = 0;
  int ret = ckb_load_cell(NULL, &len, 0, 1, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_INDEX_OUT_OF_BOUND) {
    DEBUG("Transaction has more than one input cell using current lock!");
    return ERROR_TRANSACTION;
  }
  len = 0;
  ret = ckb_load_cell(NULL, &len, 0, 1, CKB_SOURCE_GROUP_OUTPUT);
  if (ret != CKB_INDEX_OUT_OF_BOUND) {
    DEBUG("Transaction has more than one output cell using current lock!");
    return ERROR_TRANSACTION;
  }

  unsigned char script[BUFFER_SIZE];
  len = BUFFER_SIZE;
  ret = ckb_checked_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    DEBUG("molecule verification failure!");
    return ERROR_ENCODING;
  }
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

  if (args_bytes_seg.size < 44) {
    DEBUG("Script args must at least be 44 bytes long!");
    return ERROR_ENCODING;
  }
  const uint8_t *code_hash = args_bytes_seg.ptr;
  uint8_t hash_type = args_bytes_seg.ptr[32];
  uint8_t identity_size = args_bytes_seg.ptr[33];
  uint16_t aggregator_number = *((uint16_t *)(&args_bytes_seg.ptr[34]));
  uint32_t block_intervals = *((uint32_t *)(&args_bytes_seg.ptr[36]));
  int interval_uses_seconds = (block_intervals & 0x80000000) != 0;
  block_intervals &= 0x7FFFFFFF;
  uint32_t data_info_offset = *((uint32_t *)(&args_bytes_seg.ptr[40]));
  if (args_bytes_seg.size != 44 + identity_size * aggregator_number) {
    DEBUG("Script args has invalid length!");
    return ERROR_ENCODING;
  }

  // Extract current aggregator index together with signature from the first
  // witness
  uint8_t witness[BUFFER_SIZE];
  len = BUFFER_SIZE;
  ret = ckb_load_witness(witness, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  size_t readed_len = len;
  if (readed_len > BUFFER_SIZE) {
    readed_len = BUFFER_SIZE;
  }
  // Assuming the witness is in WitnessArgs structure, we are doing some
  // shortcuts here to support bigger witness.
  if (readed_len < 20) {
    DEBUG("Invalid witness length!");
    return ERROR_ENCODING;
  }
  uint32_t lock_length = *((uint32_t *)(&witness[16]));
  if (readed_len < 20 + lock_length) {
    DEBUG("Witness lock part is far tooooo long!");
    return ERROR_ENCODING;
  }
  // The lock field in WitnessArgs for current PoA script, contains a variable
  // length signature.
  const uint8_t *signature = &witness[20];
  size_t signature_size = lock_length;
  size_t remaining_offset = 20 + lock_length;

  // Check that current aggregator is indeed due to issuing new block.
  uint8_t last_block_info[10];
  len = 10;
  ret = ckb_load_cell_data(last_block_info, &len, data_info_offset, 0,
                           CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len < 10) {
    DEBUG("Invalid input block info!");
    return ERROR_ENCODING;
  }
  uint64_t last_time = *((uint64_t *)last_block_info);
  uint16_t last_aggregator_index = *((uint16_t *)(&last_block_info[8]));

  uint8_t current_block_info[10];
  len = 10;
  ret = ckb_load_cell_data(current_block_info, &len, data_info_offset, 0,
                           CKB_SOURCE_GROUP_OUTPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len < 10) {
    DEBUG("Invalid output block info!");
    return ERROR_ENCODING;
  }
  uint64_t current_timestamp = *((uint64_t *)current_block_info);
  uint16_t current_aggregator_index = *((uint16_t *)(&current_block_info[8]));
  if (current_aggregator_index >= aggregator_number) {
    DEBUG("Invalid aggregator index!");
    return ERROR_ENCODING;
  }

  // Since is used to ensure aggregators wait till the correct time.
  uint64_t since = 0;
  len = 8;
  ret = ckb_load_input_by_field(((uint8_t *)&since), &len, 0, 0,
                                CKB_SOURCE_GROUP_INPUT, CKB_INPUT_FIELD_SINCE);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 8) {
    DEBUG("Invalid loading since!");
    return ERROR_ENCODING;
  }
  if (interval_uses_seconds) {
    if (since >> 56 != 0x40) {
      DEBUG("PoA requires absolute timestamp since!");
      return ERROR_ENCODING;
    }
  } else {
    if (since >> 56 != 0) {
      DEBUG("PoA requires absolute block number since!");
      return ERROR_ENCODING;
    }
  }
  since &= 0x00FFFFFFFFFFFFFF;
  uint64_t duration =
      ((uint64_t)current_aggregator_index + (uint64_t)aggregator_number -
       (uint64_t)last_aggregator_index) *
      ((uint64_t)block_intervals);
  if (since < duration + last_time) {
    DEBUG("Invalid time!");
    return ERROR_ENCODING;
  }
  if (current_timestamp != since) {
    DEBUG("Invalid current time!");
    return ERROR_ENCODING;
  }

  // Different from our current scripts, this PoA script will actually skip
  // the signature part when hashing for signing message, instead of filling the
  // signature with all zeros.
  blake2b_state message_ctx;
  blake2b_init(&message_ctx, 32);
  blake2b_update(&message_ctx, witness, 22);
  // If we have loaded some witness parts that are after the signature, we will
  // try to use them.
  if (remaining_offset < readed_len) {
    blake2b_update(&message_ctx, &witness[remaining_offset],
                   readed_len - remaining_offset);
    remaining_offset = readed_len;
  }
  if (remaining_offset < len) {
    ret = load_and_hash_witness(&message_ctx, remaining_offset, 0,
                                CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  return validate_signature(
      code_hash, hash_type, signature, signature_size,
      &args_bytes_seg.ptr[44 + current_aggregator_index * identity_size],
      identity_size, &message_ctx);
}
