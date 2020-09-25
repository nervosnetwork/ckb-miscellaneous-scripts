// note, this macro must be same as in ckb_syscall.h
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <stddef.h>
#include <stdint.h>
#include <blockchain.h>
#include <assert.h>

static inline long __internal_syscall(long n, long _a0, long _a1, long _a2,
                                      long _a3, long _a4, long _a5) {
    return 0;
}

#define syscall(n, a, b, c, d, e, f)                                           \
  __internal_syscall(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
                     (long)(f))

int ckb_exit(int8_t code);

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  assert(offset == 0);
  uint8_t* p = (uint8_t*)addr;
  for (int i = 0; i < 32; i++) {
    p[i] = 0;
  }
  *len = 32;
  return 0;
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index, size_t source);

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index, size_t source);

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index, size_t source);

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index, size_t source) {
  return 0;
}

mol_seg_t build_args_bytes() {
  uint8_t args[32] = {0};

  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Bytes_init(&b);
  for (int i = 0; i < 32; i++) {
    MolBuilder_Bytes_push(&b, args[i]);
  }
  res = MolBuilder_Bytes_build(b);
  return res.seg;
}


int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  mol_builder_t b;
  mol_seg_res_t res;

  assert(offset == 0);

  MolBuilder_Script_init(&b);
  uint8_t code_hash[32] = {0};
  uint8_t hash_type = 0;

  MolBuilder_Script_set_code_hash(&b, code_hash, 32);
  MolBuilder_Script_set_hash_type(&b, hash_type);
  mol_seg_t bytes = build_args_bytes();
  MolBuilder_Script_set_args(&b, bytes.ptr, bytes.size);

  res = MolBuilder_Script_build(b);
  assert(res.errno == 0);

  if (*len < res.seg.size) {
    return -1;
  }
  memcpy(addr, res.seg.ptr, res.seg.size);
  *len = res.seg.size;

  free(res.seg.ptr);
  free(bytes.ptr);
  return 0;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field);

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field);

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field);

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source);

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source);

int ckb_debug(const char* s);

/* load the actual witness for the current type verify group.
   use this instead of ckb_load_witness if type contract needs args to verify input/output.
 */
int load_actual_type_witness(uint8_t *buf, uint64_t *len, size_t index,
                             size_t *type_source);


int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index);

int ckb_calculate_inputs_len() {
  return 0;
}

int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field) {
  return CKB_INDEX_OUT_OF_BOUND;
}


#define MIN(a, b) ((a) > (b) ? (b) : (a))
// can't bigger than block
// around 600K
#define MAX_CELL_SIZE 655350

static uint8_t s_input_cell_data[MAX_CELL_SIZE];
static uint32_t s_input_cell_length = 0;

int fill_input_cell_data(uint8_t* data, size_t length) {
  if (length > sizeof(s_input_cell_data)) {
    return -1;
  }
  memcpy(s_input_cell_data, data, length);
  s_input_cell_length = length;
  return 0;
}

static uint8_t s_output_cell_data[MAX_CELL_SIZE];
static uint32_t s_output_cell_length = 0;

int fill_output_cell_data(uint8_t* data, size_t length) {
  if (length > sizeof(s_output_cell_data)) {
    return -1;
  }
  memcpy(s_output_cell_data, data, length);
  s_output_cell_length = length;
  return 0;
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  if (index > 0) {
    return CKB_INDEX_OUT_OF_BOUND;
  }

  if (CKB_SOURCE_GROUP_INPUT == source) {
    size_t max_read_length = MIN(*len, s_input_cell_length - offset);
    memcpy(addr, s_input_cell_data + offset, max_read_length);
    *len = max_read_length;
  } else if (CKB_SOURCE_GROUP_OUTPUT == source) {
    size_t max_read_length = MIN(*len, s_output_cell_length - offset);
    memcpy(addr, s_output_cell_data + offset, max_read_length);
    *len = max_read_length;
  } else {
  }
  return 0;
}


#endif

