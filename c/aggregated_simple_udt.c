
// link to the spec(draft):
// https://cryptape.quip.com/dBL9AmsVX8WO/Simple-UDT-Extension-0001-Aggregated-Cell
#include "blockchain.h"
#include "stdlib.h"

#ifdef CKB_USE_SIM
#include "ckb_consts.h"
#include "ckb_syscall_agg_sudt.h"
#define ASSERT assert
#else
#include "ckb_syscalls.h"
#define ASSERT(a) (void)0
#endif

// Common error codes
#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_ONLY_INIT -50
#define ERROR_OVERFLOWING -51
#define ERROR_AMOUNT -52
#define ERROR_INVALID_OUTPUT -53
#define ERROR_TOO_MANY_SUDT -54
#define ERROR_ENCODING_2 -55
#define ERROR_ENCODING_3 -56
#define ERROR_ENCODING_4 -57

// We are limiting the script size loaded to be 32KB at most. This should be
// more than enough. We are also using blake2b with 256-bit hash here, which is
// the same as CKB.
#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_SIZE (48 * 8192)
#define MAX_SUDT_ENTRY_COUNT 12800
#define SUDT_ID_SIZE 32
#define CHECK_ADD_ASSIGN(sum, v)               \
  do {                                         \
    (sum) += (v);                              \
    if ((sum) < (v)) return ERROR_OVERFLOWING; \
  } while (0)

typedef unsigned __int128 uint128_t;

// The ID is actually the hash of type script. It's also the ID of SUDT.
typedef struct sudt_entry_t {
  uint8_t id[SUDT_ID_SIZE];
  uint128_t amount;
} sudt_entry_t;

int compare_sudt_entry(const void* a, const void* b) {
  return memcmp(((sudt_entry_t*)a)->id, ((sudt_entry_t*)b)->id, SUDT_ID_SIZE);
}

// this is the data struct which we allocate at the beginning on stack
// after that, we don't need any memory allocation any more
typedef struct sudt_container_t {
  uint32_t count;
  sudt_entry_t buff[MAX_SUDT_ENTRY_COUNT];
} sudt_container_t;

void init(sudt_container_t* c) { c->count = 0; }

// failed only when not enough memory
int push(sudt_container_t* container, sudt_entry_t* from_input_cell,
         uint32_t count) {
  if ((container->count + count) > MAX_SUDT_ENTRY_COUNT) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(container->buff, from_input_cell,
         count * sizeof(struct sudt_container_t));
  container->count += count;
  return CKB_SUCCESS;
}

// load data by ckb_load_cell_data directly, avoid extra copying
int load(sudt_container_t* container, size_t index, size_t source) {
  uint32_t sudt_length = 0;
  uint64_t len = sizeof(uint32_t);
  int ret = ckb_load_cell_data((uint8_t*)&sudt_length, &len, 0, index, source);
  if (ret == CKB_INDEX_OUT_OF_BOUND) return ret;
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != sizeof(uint32_t)) {
    return ERROR_ENCODING_3;
  }
  // the buff is not enough to hold remaining SUDT from one cell
  uint64_t buff_left =
      (MAX_SUDT_ENTRY_COUNT - container->count) * sizeof(sudt_entry_t);
  if (sudt_length > buff_left) {
    return ERROR_TOO_MANY_SUDT;
  }
  len = buff_left;
  ret = ckb_load_cell_data(container->buff + container->count, &len, 4, index,
                           source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ASSERT(len % sizeof(sudt_entry_t) == 0);
  container->count += len / sizeof(sudt_entry_t);
  // it's impossible, but we still check it here
  if (container->count > MAX_SUDT_ENTRY_COUNT) {
    ASSERT(false);
    return ERROR_TOO_MANY_SUDT;
  }
  return CKB_SUCCESS;
}

// 1. Sort the SUDT in container, according to the key (SUDT ID in sudt_entry_t)
// 2. Add all amounts for same SUDT ID in a row, to the first one
// for example, memory layout is: [SUDT A ID (1)] [SUDT A ID (2)] [SUDT A ID
// (3)] ... ... SUDT A ID (1) will be updated only. The remaining parts((2),
// (3)) after adding will be removed at next step.
// 3. Remove duplicated SUDT((2), (3)) by treating them as "gap"(do nothing)
// 4. Update "len"
int merge(sudt_container_t* container) {
  // make sure there are at lease 2 entries in container
  if (container->count <= 1) return CKB_SUCCESS;
  qsort(container->buff, container->count, sizeof(sudt_entry_t),
        compare_sudt_entry);
  // all amounts added to this position for same id of SUDT
  sudt_entry_t* write_pos;
  // iterator through whole container
  sudt_entry_t* read_pos;
  // end flag, it's an invalid position.
  sudt_entry_t* end_pos;

  write_pos = container->buff;
  end_pos = container->buff + container->count;
  for (read_pos = write_pos + 1; read_pos < end_pos; read_pos++) {
    if (compare_sudt_entry(write_pos->id, read_pos->id) == 0) {
      CHECK_ADD_ASSIGN(write_pos->amount, read_pos->amount);
    } else {
      // meet new SUDT, move this one if gap is bigger enough(> 0)
      ASSERT(read_pos > write_pos);
      int gap = read_pos - write_pos - 1;
      if (gap > 0) {
        // enough gap, move. memory layout: [write_pos] [sudt] [sudt] [sudt]
        // [read_pos]
        write_pos++;
        *write_pos = *read_pos;
      } else {
        // no gap, memory layout: [write_pos][read_pos][sudt]
        write_pos = read_pos;
      }
    }
  }
  ASSERT(write_pos >= container->buff);
  container->count = (write_pos - container->buff) + 1;
  return CKB_SUCCESS;
}

// subtracts every sudt entry (from output cell) from input cell sudt entries,
// failed if:
// 1. it can't find corresponding sudt id in input, OR
// 2. after subtracting, the amount is below zero for a specific udt id
int subtract(sudt_container_t* container, sudt_entry_t* from_output_cell,
             uint32_t size) {
  for (uint32_t i = 0; i < size; i++) {
    sudt_entry_t* cell = from_output_cell + i;
    sudt_entry_t* match =
        (sudt_entry_t*)bsearch(cell, container->buff, container->count,
                               sizeof(sudt_entry_t), compare_sudt_entry);
    if (match == NULL) {
      return ERROR_INVALID_OUTPUT;
    }
    if (match->amount < cell->amount) {
      return ERROR_AMOUNT;
    }
    match->amount -= cell->amount;
  }
  // ideally, all amounts in container should be >= 0, but we don't need to
  // check
  return CKB_SUCCESS;
}

int inner_main() {
  // First, let's load current running script, so we can extract owner lock
  // script hash from script args.
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
  script_seg.ptr = (uint8_t*)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != BLAKE2B_BLOCK_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  // With owner lock script extracted, we will look through each input in the
  // current transaction to see if any unlocked cell uses owner lock.
  int owner_mode = 0;
  size_t i = 0;
  while (1) {
    uint8_t buffer[BLAKE2B_BLOCK_SIZE];
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    // There are 2 points worth mentioning here:
    //
    // * First, we are using the checked version of CKB syscalls, the checked
    // versions will return an error if our provided buffer is not enough to
    // hold all returned data. This can help us ensure that we are processing
    // enough data here.
    // * Second, `CKB_CELL_FIELD_LOCK_HASH` is used here to directly load the
    // lock script hash, so we don't have to manually calculate the hash again
    // here.
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

  // When owner mode is triggered, we won't perform any checks here, the owner
  // is free to make any changes here, including token issurance, minting, etc.
  if (owner_mode) {
    return CKB_SUCCESS;
  }

  sudt_container_t container;
  init(&container);

  // When the owner mode is not enabled, however, we will then need to ensure
  // the sum of all input tokens is not smaller than the sum of all output
  // tokens. First, let's loop through all input cells containing current UDTs,
  // and gather the sum of all input tokens.
  i = 0;
  while (1) {
    ret = load(&container, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = merge(&container);
    if (ret != CKB_SUCCESS) return ret;
    i += 1;
  }

  // re-use "script" buff
  sudt_entry_t* output_sudt = (sudt_entry_t*)script;
  uint32_t output_sudt_length = sizeof(script);

  i = 0;
  while (1) {
    uint32_t sudt_length = 0;
    uint64_t len = sizeof(uint32_t);
    int ret = ckb_load_cell_data((uint8_t*)&sudt_length, &len, 0, i,
                                 CKB_SOURCE_GROUP_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != sizeof(uint32_t)) {
      return ERROR_ENCODING_4;
    }
    if ((sudt_length * sizeof(struct sudt_entry_t)) > output_sudt_length) {
      return ERROR_TOO_MANY_SUDT;
    }
    len = output_sudt_length;
    ret = ckb_load_cell_data(output_sudt, &len, 4, i, CKB_SOURCE_GROUP_OUTPUT);
    // here don't need to check CKB_INDEX_OUT_OF_BOUND because we're sure there
    // must be data
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != (sudt_length * sizeof(struct sudt_entry_t))) {
      return ERROR_ENCODING_2;
    }
    ret = subtract(&container, output_sudt, sudt_length);
    if (ret != CKB_SUCCESS) return ret;
    i += 1;
  }

  return CKB_SUCCESS;
}

#ifndef CKB_USE_SIM
int main() { return inner_main(); }
#endif
