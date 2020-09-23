
#include "stdlib.h"
#include "blockchain.h"

#ifdef CKB_USE_SIM
#include "ckb_consts.h"
#include "ckb_syscall_sim.h"
#else
#include "ckb_syscalls.h"
#endif

// Common error codes
#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_ONLY_INIT -50
#define ERROR_OVERFLOWING -51
#define ERROR_AMOUNT -52


#define MAX_UDT_TYPE_LIMIT 8192
// TODO: how much udt entries are allowed?
#define MAX_UDT_ENTRY_COUNT (MAX_UDT_TYPE_LIMIT*4)
#define UDT_TYPE_SIZE 32


typedef unsigned __int128 uint128_t;

// the udt type is actually the hash of type script
typedef struct udt_entry_t {
  uint8_t type[UDT_TYPE_SIZE];
  uint128_t amount;
} udt_entry_t;

int compare_udt_entry(const void* a, const void* b) {
  return memcmp(((udt_entry_t*)a)->type, ((udt_entry_t*)b)->type, UDT_TYPE_SIZE);
}

// this is the data struct which we allocate at the beginning on stack
// after that, we don't need any memory allocation any more
typedef struct udt_container_t {
  uint32_t count;
  udt_entry_t buff[MAX_UDT_ENTRY_COUNT];
} udt_container_t;

// failed only when not enough memory
int push(udt_container_t* container, udt_entry_t* from_input_cell, uint32_t count) {
  if ((container->count + count) > MAX_UDT_ENTRY_COUNT) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(container->buff, from_input_cell, count*sizeof(struct udt_container_t));
  container->count += count;
  return CKB_SUCCESS;
}

// 1. Sort the udt in container, according to the key "udt_t type"
// 2. Add all amounts in same udt in a row
// 3. remove duplicated udt, leave only one for one udt type.
// 4. update "len"
// merge never fail
void merge(udt_container_t* container) {
  qsort(container->buff, container->count, sizeof(udt_entry_t), compare_udt_entry);
}

// subtracts every udt entry (from output cell) from input cell udt entries, failed if:
// 1. it can't find corresponding udt type in input, OR
// 2. after subtracting, the amount is below zero for a specific udt type
int subtract(udt_container_t* container, udt_entry_t* from_output_cell, uint32_t size) {
  return 0;
}

int main() {
  return 0;
}
