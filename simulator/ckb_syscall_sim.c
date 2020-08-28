#include <stddef.h>
#include <stdint.h>

static inline long __internal_syscall(long n, long _a0, long _a1, long _a2,
                                      long _a3, long _a4, long _a5) {
    return 0;
}

#define syscall(n, a, b, c, d, e, f)                                           \
  __internal_syscall(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
                     (long)(f))

int ckb_exit(int8_t code) {
    return 0;
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
    return 0;
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
    return 0;
}

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source) {
    return 0;
}

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source) {
    return 0;
}

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source) {
    return 0;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
    return 0;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
    return 0;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
    return 0;
}

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field) {
    return 0;
}

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
    return 0;
}

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source) {
    return 0;
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
    return 0;
}

int ckb_debug(const char* s) {
    return 0;
}

/* load the actual witness for the current type verify group.
   use this instead of ckb_load_witness if type contract needs args to verify input/output.
 */
int load_actual_type_witness(uint8_t *buf, uint64_t *len, size_t index,
                             size_t *type_source) {
    return 0;
}


int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index) {
    return 0;
}

int ckb_calculate_inputs_len() {
    return 0;
}
