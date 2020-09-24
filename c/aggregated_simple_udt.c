
// link to the spec(draft):
// https://cryptape.quip.com/dBL9AmsVX8WO/Simple-UDT-Extension-0001-Aggregated-Cell
#include "stdlib.h"
#include "blockchain.h"

#ifdef CKB_USE_SIM
#include "ckb_consts.h"
#include "ckb_syscall_sim.h"
#define ASSERT assert
#else
#include "ckb_syscalls.h"
#define ASSERT (void)0
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


#define MAX_SUDT_TYPE_LIMIT 8192
// TODO: how much sudt entries are allowed?
#define MAX_SUDT_ENTRY_COUNT (MAX_SUDT_TYPE_LIMIT*4)
#define SUDT_ID_SIZE 32
#define CHECK_ADD_ASSIGN(sum, v) do {(sum) += (v); if ((sum) < (v)) return ERROR_OVERFLOWING;} while(0)

typedef unsigned __int128 uint128_t;

// the type is actually the hash of type script. It's also the ID of SUDT.
typedef struct sudt_entry_t {
  uint8_t id[SUDT_ID_SIZE];
  uint128_t amount;
} sudt_entry_t;

int compare_sudt_entry(const void* a, const void* b) {
  return memcmp(((sudt_entry_t*)a)->id, ((sudt_entry_t*)b)->id, SUDT_ID_SIZE);
}

typedef int (*cmp_func_t)(const void* a, const void* b);

void *bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp) {
  const char *pivot;
  int result;

  while (num > 0) {
    pivot = base + (num >> 1) * size;
    result = cmp(key, pivot);

    if (result == 0)
      return (void *)pivot;

    if (result > 0) {
      base = pivot + size;
      num--;
    }
    num >>= 1;
  }

  return NULL;
}


// this is the data struct which we allocate at the beginning on stack
// after that, we don't need any memory allocation any more
typedef struct sudt_container_t {
  uint32_t count;
  sudt_entry_t buff[MAX_SUDT_ENTRY_COUNT];
} sudt_container_t;

// failed only when not enough memory
int push(sudt_container_t* container, sudt_entry_t* from_input_cell, uint32_t count) {
  if ((container->count + count) > MAX_SUDT_ENTRY_COUNT) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(container->buff, from_input_cell, count*sizeof(struct sudt_container_t));
  container->count += count;
  return CKB_SUCCESS;
}

// load data by ckb_load_cell_data directly, avoid extra copying
int load(sudt_container_t* container, size_t index, size_t source) {
  uint32_t sudt_length = 0;
  uint64_t len = sizeof(uint32_t);
  int ret = ckb_load_cell_data((uint8_t *)&sudt_length, &len, 0, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != sizeof(uint32_t)) {
    return ERROR_ENCODING;
  }
  // the buff is not enough to hold remaining SUDT from one cell
  uint64_t buff_left = (MAX_SUDT_ENTRY_COUNT - container->count)*sizeof(sudt_entry_t);
  if (sudt_length > buff_left) {
    return ERROR_TOO_MANY_SUDT;
  }
  len = buff_left;
  ret = ckb_load_cell_data(container->buff+container->count, &len, 4, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  container->count += len/sizeof(sudt_entry_t);
  // it's impossible, but we still check it here
  if (container->count > MAX_SUDT_ENTRY_COUNT) {
    ASSERT(false);
    return ERROR_TOO_MANY_SUDT;
  }
  return CKB_SUCCESS;
}

// 1. Sort the sudt in container, according to the key SUDT ID(sudt_entry_t)
// 2. Add all amounts for same SUDT ID in a row, to the first one
// for example, memory layout is: [SUDT A ID (1)] [SUDT A ID (2)] [SUDT A ID (3)] ... ...
// SUDT A ID (1) will be updated only. The remaining parts((2), (3)) after adding will be discarded at next step.
// 3. remove duplicated SUDT((2), (3))
// 4. update "len"
int merge(sudt_container_t* container) {
  // make sure there are at lease 2 entries in container
  if (container->count <= 1)
    return CKB_SUCCESS;
  qsort(container->buff, container->count, sizeof(sudt_entry_t), compare_sudt_entry);
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
      // meet new udt, move this one if possible
      ASSERT(read_pos > write_pos);
      int gap = read_pos - write_pos - sizeof(sudt_entry_t);
      if (gap > 0) {
        // enough gap, move. memory layout: [write_pos] [sudt] [sudt] [sudt] [read_pos]
        write_pos++;
        *write_pos = *read_pos;
      } else {
        // no gap, memory layout: [write_pos][read_pos][sudt]
        write_pos = read_pos;
      }
    }
  }
  ASSERT(write_pos >= container->buff);
  container->count = (write_pos - container->buff)/sizeof(sudt_entry_t) + 1;
  return CKB_SUCCESS;
}

// subtracts every sudt entry (from output cell) from input cell sudt entries, failed if:
// 1. it can't find corresponding sudt id in input, OR
// 2. after subtracting, the amount is below zero for a specific udt id
int subtract(sudt_container_t* container, sudt_entry_t* from_output_cell, uint32_t size) {
  for (uint32_t i = 0; i < size; i++) {
    sudt_entry_t* cell = from_output_cell+i;
    sudt_entry_t* match = (sudt_entry_t*) bsearch(cell, container->buff, container->count,
                                                  sizeof(sudt_entry_t), compare_sudt_entry);
    if (match == NULL) {
      return ERROR_INVALID_OUTPUT;
    }
    if (match->amount < cell->amount) {
      return ERROR_AMOUNT;
    }
    match->amount -= cell->amount;
  }
  // ideally, all amounts in container should be >= 0, but we don't need to check
  return CKB_SUCCESS;
}

int main() {
  return 0;
}
