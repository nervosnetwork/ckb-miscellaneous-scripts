#ifndef CKB_MISCELLANEOUS_SCRIPTS_C_CKB_SYSCALLS_DECL_ONLY_H_
#define CKB_MISCELLANEOUS_SCRIPTS_C_CKB_SYSCALLS_DECL_ONLY_H_

#include <stddef.h>
#include <stdint.h>

#include "ckb_consts.h"

int ckb_checked_load_tx_hash(void* addr, uint64_t* len, size_t offset);

int ckb_checked_load_script_hash(void* addr, uint64_t* len, size_t offset);

int ckb_checked_load_cell(void* addr, uint64_t* len, size_t offset,
                          size_t index, size_t source);

int ckb_checked_load_input(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source);

int ckb_checked_load_header(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source);

int ckb_checked_load_witness(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source);

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);
int ckb_checked_load_transaction(void* addr, uint64_t* len, size_t offset);
int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field);

int ckb_checked_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                                     size_t index, size_t source,
                                     size_t field);

int ckb_checked_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                                    size_t index, size_t source, size_t field);

int ckb_checked_load_cell_data(void* addr, uint64_t* len, size_t offset,
                               size_t index, size_t source);
int ckb_load_actual_type_witness(uint8_t* buf, uint64_t* len, size_t index,
                                 size_t* type_source);
int ckb_calculate_inputs_len();

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index);

int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index);


int ckb_exit(int8_t code);

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset);
int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source);

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source);
int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source);

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source);
int ckb_load_script(void* addr, uint64_t* len, size_t offset);

int ckb_load_transaction(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field);

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field);

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field);

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source);

int ckb_debug(const char* s);

#endif //CKB_MISCELLANEOUS_SCRIPTS_C_CKB_SYSCALLS_DECL_ONLY_H_
