#ifndef CKB_MISCELLANEOUS_SCRIPTS_SIMULATOR_MOLECULE_DECL_ONLY_H_
#define CKB_MISCELLANEOUS_SCRIPTS_SIMULATOR_MOLECULE_DECL_ONLY_H_

#include <stdbool.h>
#include <stdint.h>

#define is_le() (*(unsigned char *)&(uint16_t){1})
typedef uint32_t mol_num_t;  // Item Id
typedef uint8_t mol_errno;  // Error Number
#define MolNum UINT32_C
#define MOL_NUM_T_SIZE 4

// Bytes segment.
typedef struct {
  uint8_t *ptr;    // Pointer
  mol_num_t size;  // Full size
} mol_seg_t;

// Unpacked Union
typedef struct {
  mol_num_t item_id;  // Item Id
  mol_seg_t seg;      // Segment
} mol_union_t;

// Result for returning segment.
typedef struct {
  mol_errno errno;  // Error Number
  mol_seg_t seg;    // Segment
} mol_seg_res_t;

/* Error Numbers */

#define MOL_OK 0x00
#define MOL_ERR 0xff

#define MOL_ERR_TOTAL_SIZE 0x01
#define MOL_ERR_HEADER 0x02
#define MOL_ERR_OFFSET 0x03
#define MOL_ERR_UNKNOWN_ITEM 0x04
#define MOL_ERR_INDEX_OUT_OF_BOUNDS 0x05
#define MOL_ERR_FIELD_COUNT 0x06
#define MOL_ERR_DATA 0x07

/* Utilities. */

mol_num_t mol_unpack_number(const uint8_t *src);

/*
 * Core functions.
 */

/* Verify Functions. */

// Verify Array / Struct.
mol_errno mol_verify_fixed_size(const mol_seg_t *input, mol_num_t total_size);

// Verify FixVec.
mol_errno mol_fixvec_verify(const mol_seg_t *input, mol_num_t item_size);
bool mol_option_is_none(const mol_seg_t *input);
mol_union_t mol_union_unpack(const mol_seg_t *input);
mol_num_t mol_fixvec_length(const mol_seg_t *input);
mol_num_t mol_dynvec_length(const mol_seg_t *input);
mol_num_t mol_table_actual_field_count(const mol_seg_t *input);
bool mol_table_has_extra_fields(const mol_seg_t *input, mol_num_t field_count);
mol_seg_t mol_slice_by_offset(const mol_seg_t *input, mol_num_t offset,
                              mol_num_t size);
mol_seg_res_t mol_fixvec_slice_by_index(const mol_seg_t *input,
                                        mol_num_t item_size,
                                        mol_num_t item_index);
mol_seg_res_t mol_dynvec_slice_by_index(const mol_seg_t *input,
                                        mol_num_t item_index);
mol_seg_t mol_table_slice_by_index(const mol_seg_t *input,
                                   mol_num_t field_index);

mol_seg_t mol_fixvec_slice_raw_bytes(const mol_seg_t *input);


// molecule-builder.h
typedef struct {
  uint8_t *data_ptr;    // Data Pointer
  mol_num_t data_used;  // Data Used
  mol_num_t data_cap;   // Data Capacity

  mol_num_t *number_ptr;  // A Pointer of Numbers
  mol_num_t number_used;  // Numbers used
  mol_num_t number_cap;   // Numbers Capacity
} mol_builder_t;

/* Utilities. */

void mol_pack_number(uint8_t *dst, mol_num_t *num);
/*
 * Core functions.
 */

void mol_builder_discard(mol_builder_t builder);

void mol_builder_initialize_fixed_size(mol_builder_t *builder,
                                       mol_num_t fixed_size);

void mol_union_builder_initialize(mol_builder_t *builder,
                                  mol_num_t data_capacity, mol_num_t item_id,
                                  const uint8_t *default_ptr,
                                  mol_num_t default_len);

void mol_builder_initialize_with_capacity(mol_builder_t *builder,
                                          mol_num_t data_capacity,
                                          mol_num_t number_capacity);

void mol_fixvec_builder_initialize(mol_builder_t *builder,
                                   mol_num_t data_capacity);

void mol_table_builder_initialize(mol_builder_t *builder,
                                  mol_num_t data_capacity,
                                  mol_num_t field_count);

void mol_option_builder_set(mol_builder_t *builder, const uint8_t *data_ptr,
                            mol_num_t data_len);

void mol_union_builder_set_byte(mol_builder_t *builder, mol_num_t item_id,
                                uint8_t data);

void mol_union_builder_set(mol_builder_t *builder, mol_num_t item_id,
                           const uint8_t *data_ptr, mol_num_t data_len);

void mol_builder_set_byte_by_offset(mol_builder_t *builder, mol_num_t offset,
                                    uint8_t data);

void mol_builder_set_by_offset(mol_builder_t *builder, mol_num_t offset,
                               const uint8_t *data_ptr, mol_num_t length);

void mol_fixvec_builder_push_byte(mol_builder_t *builder, uint8_t data);

void mol_fixvec_builder_push(mol_builder_t *builder, const uint8_t *data_ptr,
                             mol_num_t length);

void mol_dynvec_builder_push(mol_builder_t *builder, const uint8_t *data_ptr,
                             mol_num_t data_len);
void mol_table_builder_add_byte(mol_builder_t *builder, mol_num_t field_index,
                                uint8_t data);

void mol_table_builder_add(mol_builder_t *builder, mol_num_t field_index,
                           const uint8_t *data_ptr, mol_num_t data_len);
mol_seg_res_t mol_builder_finalize_simple(mol_builder_t builder);

mol_seg_res_t mol_fixvec_builder_finalize(mol_builder_t builder);
mol_seg_res_t mol_dynvec_builder_finalize(mol_builder_t builder);

// blockchain-api.h
#define MolReader_Uint32_verify(s, c) mol_verify_fixed_size(s, 4)
#define MolReader_Uint32_get_nth0(s) mol_slice_by_offset(s, 0, 1)
#define MolReader_Uint32_get_nth1(s) mol_slice_by_offset(s, 1, 1)
#define MolReader_Uint32_get_nth2(s) mol_slice_by_offset(s, 2, 1)
#define MolReader_Uint32_get_nth3(s) mol_slice_by_offset(s, 3, 1)
#define MolReader_Uint64_verify(s, c) mol_verify_fixed_size(s, 8)
#define MolReader_Uint64_get_nth0(s) mol_slice_by_offset(s, 0, 1)
#define MolReader_Uint64_get_nth1(s) mol_slice_by_offset(s, 1, 1)
#define MolReader_Uint64_get_nth2(s) mol_slice_by_offset(s, 2, 1)
#define MolReader_Uint64_get_nth3(s) mol_slice_by_offset(s, 3, 1)
#define MolReader_Uint64_get_nth4(s) mol_slice_by_offset(s, 4, 1)
#define MolReader_Uint64_get_nth5(s) mol_slice_by_offset(s, 5, 1)
#define MolReader_Uint64_get_nth6(s) mol_slice_by_offset(s, 6, 1)
#define MolReader_Uint64_get_nth7(s) mol_slice_by_offset(s, 7, 1)
#define MolReader_Uint128_verify(s, c) mol_verify_fixed_size(s, 16)
#define MolReader_Uint128_get_nth0(s) mol_slice_by_offset(s, 0, 1)
#define MolReader_Uint128_get_nth1(s) mol_slice_by_offset(s, 1, 1)
#define MolReader_Uint128_get_nth2(s) mol_slice_by_offset(s, 2, 1)
#define MolReader_Uint128_get_nth3(s) mol_slice_by_offset(s, 3, 1)
#define MolReader_Uint128_get_nth4(s) mol_slice_by_offset(s, 4, 1)
#define MolReader_Uint128_get_nth5(s) mol_slice_by_offset(s, 5, 1)
#define MolReader_Uint128_get_nth6(s) mol_slice_by_offset(s, 6, 1)
#define MolReader_Uint128_get_nth7(s) mol_slice_by_offset(s, 7, 1)
#define MolReader_Uint128_get_nth8(s) mol_slice_by_offset(s, 8, 1)
#define MolReader_Uint128_get_nth9(s) mol_slice_by_offset(s, 9, 1)
#define MolReader_Uint128_get_nth10(s) mol_slice_by_offset(s, 10, 1)
#define MolReader_Uint128_get_nth11(s) mol_slice_by_offset(s, 11, 1)
#define MolReader_Uint128_get_nth12(s) mol_slice_by_offset(s, 12, 1)
#define MolReader_Uint128_get_nth13(s) mol_slice_by_offset(s, 13, 1)
#define MolReader_Uint128_get_nth14(s) mol_slice_by_offset(s, 14, 1)
#define MolReader_Uint128_get_nth15(s) mol_slice_by_offset(s, 15, 1)
#define MolReader_Byte32_verify(s, c) mol_verify_fixed_size(s, 32)
#define MolReader_Byte32_get_nth0(s) mol_slice_by_offset(s, 0, 1)
#define MolReader_Byte32_get_nth1(s) mol_slice_by_offset(s, 1, 1)
#define MolReader_Byte32_get_nth2(s) mol_slice_by_offset(s, 2, 1)
#define MolReader_Byte32_get_nth3(s) mol_slice_by_offset(s, 3, 1)
#define MolReader_Byte32_get_nth4(s) mol_slice_by_offset(s, 4, 1)
#define MolReader_Byte32_get_nth5(s) mol_slice_by_offset(s, 5, 1)
#define MolReader_Byte32_get_nth6(s) mol_slice_by_offset(s, 6, 1)
#define MolReader_Byte32_get_nth7(s) mol_slice_by_offset(s, 7, 1)
#define MolReader_Byte32_get_nth8(s) mol_slice_by_offset(s, 8, 1)
#define MolReader_Byte32_get_nth9(s) mol_slice_by_offset(s, 9, 1)
#define MolReader_Byte32_get_nth10(s) mol_slice_by_offset(s, 10, 1)
#define MolReader_Byte32_get_nth11(s) mol_slice_by_offset(s, 11, 1)
#define MolReader_Byte32_get_nth12(s) mol_slice_by_offset(s, 12, 1)
#define MolReader_Byte32_get_nth13(s) mol_slice_by_offset(s, 13, 1)
#define MolReader_Byte32_get_nth14(s) mol_slice_by_offset(s, 14, 1)
#define MolReader_Byte32_get_nth15(s) mol_slice_by_offset(s, 15, 1)
#define MolReader_Byte32_get_nth16(s) mol_slice_by_offset(s, 16, 1)
#define MolReader_Byte32_get_nth17(s) mol_slice_by_offset(s, 17, 1)
#define MolReader_Byte32_get_nth18(s) mol_slice_by_offset(s, 18, 1)
#define MolReader_Byte32_get_nth19(s) mol_slice_by_offset(s, 19, 1)
#define MolReader_Byte32_get_nth20(s) mol_slice_by_offset(s, 20, 1)
#define MolReader_Byte32_get_nth21(s) mol_slice_by_offset(s, 21, 1)
#define MolReader_Byte32_get_nth22(s) mol_slice_by_offset(s, 22, 1)
#define MolReader_Byte32_get_nth23(s) mol_slice_by_offset(s, 23, 1)
#define MolReader_Byte32_get_nth24(s) mol_slice_by_offset(s, 24, 1)
#define MolReader_Byte32_get_nth25(s) mol_slice_by_offset(s, 25, 1)
#define MolReader_Byte32_get_nth26(s) mol_slice_by_offset(s, 26, 1)
#define MolReader_Byte32_get_nth27(s) mol_slice_by_offset(s, 27, 1)
#define MolReader_Byte32_get_nth28(s) mol_slice_by_offset(s, 28, 1)
#define MolReader_Byte32_get_nth29(s) mol_slice_by_offset(s, 29, 1)
#define MolReader_Byte32_get_nth30(s) mol_slice_by_offset(s, 30, 1)
#define MolReader_Byte32_get_nth31(s) mol_slice_by_offset(s, 31, 1)
#define MolReader_Uint256_verify(s, c) mol_verify_fixed_size(s, 32)
#define MolReader_Uint256_get_nth0(s) mol_slice_by_offset(s, 0, 1)
#define MolReader_Uint256_get_nth1(s) mol_slice_by_offset(s, 1, 1)
#define MolReader_Uint256_get_nth2(s) mol_slice_by_offset(s, 2, 1)
#define MolReader_Uint256_get_nth3(s) mol_slice_by_offset(s, 3, 1)
#define MolReader_Uint256_get_nth4(s) mol_slice_by_offset(s, 4, 1)
#define MolReader_Uint256_get_nth5(s) mol_slice_by_offset(s, 5, 1)
#define MolReader_Uint256_get_nth6(s) mol_slice_by_offset(s, 6, 1)
#define MolReader_Uint256_get_nth7(s) mol_slice_by_offset(s, 7, 1)
#define MolReader_Uint256_get_nth8(s) mol_slice_by_offset(s, 8, 1)
#define MolReader_Uint256_get_nth9(s) mol_slice_by_offset(s, 9, 1)
#define MolReader_Uint256_get_nth10(s) mol_slice_by_offset(s, 10, 1)
#define MolReader_Uint256_get_nth11(s) mol_slice_by_offset(s, 11, 1)
#define MolReader_Uint256_get_nth12(s) mol_slice_by_offset(s, 12, 1)
#define MolReader_Uint256_get_nth13(s) mol_slice_by_offset(s, 13, 1)
#define MolReader_Uint256_get_nth14(s) mol_slice_by_offset(s, 14, 1)
#define MolReader_Uint256_get_nth15(s) mol_slice_by_offset(s, 15, 1)
#define MolReader_Uint256_get_nth16(s) mol_slice_by_offset(s, 16, 1)
#define MolReader_Uint256_get_nth17(s) mol_slice_by_offset(s, 17, 1)
#define MolReader_Uint256_get_nth18(s) mol_slice_by_offset(s, 18, 1)
#define MolReader_Uint256_get_nth19(s) mol_slice_by_offset(s, 19, 1)
#define MolReader_Uint256_get_nth20(s) mol_slice_by_offset(s, 20, 1)
#define MolReader_Uint256_get_nth21(s) mol_slice_by_offset(s, 21, 1)
#define MolReader_Uint256_get_nth22(s) mol_slice_by_offset(s, 22, 1)
#define MolReader_Uint256_get_nth23(s) mol_slice_by_offset(s, 23, 1)
#define MolReader_Uint256_get_nth24(s) mol_slice_by_offset(s, 24, 1)
#define MolReader_Uint256_get_nth25(s) mol_slice_by_offset(s, 25, 1)
#define MolReader_Uint256_get_nth26(s) mol_slice_by_offset(s, 26, 1)
#define MolReader_Uint256_get_nth27(s) mol_slice_by_offset(s, 27, 1)
#define MolReader_Uint256_get_nth28(s) mol_slice_by_offset(s, 28, 1)
#define MolReader_Uint256_get_nth29(s) mol_slice_by_offset(s, 29, 1)
#define MolReader_Uint256_get_nth30(s) mol_slice_by_offset(s, 30, 1)
#define MolReader_Uint256_get_nth31(s) mol_slice_by_offset(s, 31, 1)
#define MolReader_Bytes_verify(s, c) mol_fixvec_verify(s, 1)
#define MolReader_Bytes_length(s) mol_fixvec_length(s)
#define MolReader_Bytes_get(s, i) mol_fixvec_slice_by_index(s, 1, i)
#define MolReader_Bytes_raw_bytes(s) mol_fixvec_slice_raw_bytes(s)
mol_errno MolReader_BytesOpt_verify(const mol_seg_t *, bool);
#define MolReader_BytesOpt_is_none(s) mol_option_is_none(s)
mol_errno MolReader_BytesVec_verify(const mol_seg_t *, bool);
#define MolReader_BytesVec_length(s) mol_dynvec_length(s)
#define MolReader_BytesVec_get(s, i) mol_dynvec_slice_by_index(s, i)
#define MolReader_Byte32Vec_verify(s, c) mol_fixvec_verify(s, 32)
#define MolReader_Byte32Vec_length(s) mol_fixvec_length(s)
#define MolReader_Byte32Vec_get(s, i) mol_fixvec_slice_by_index(s, 32, i)
mol_errno MolReader_ScriptOpt_verify(const mol_seg_t *, bool);
#define MolReader_ScriptOpt_is_none(s) mol_option_is_none(s)
#define MolReader_ProposalShortId_verify(s, c) mol_verify_fixed_size(s, 10)
#define MolReader_ProposalShortId_get_nth0(s) mol_slice_by_offset(s, 0, 1)
#define MolReader_ProposalShortId_get_nth1(s) mol_slice_by_offset(s, 1, 1)
#define MolReader_ProposalShortId_get_nth2(s) mol_slice_by_offset(s, 2, 1)
#define MolReader_ProposalShortId_get_nth3(s) mol_slice_by_offset(s, 3, 1)
#define MolReader_ProposalShortId_get_nth4(s) mol_slice_by_offset(s, 4, 1)
#define MolReader_ProposalShortId_get_nth5(s) mol_slice_by_offset(s, 5, 1)
#define MolReader_ProposalShortId_get_nth6(s) mol_slice_by_offset(s, 6, 1)
#define MolReader_ProposalShortId_get_nth7(s) mol_slice_by_offset(s, 7, 1)
#define MolReader_ProposalShortId_get_nth8(s) mol_slice_by_offset(s, 8, 1)
#define MolReader_ProposalShortId_get_nth9(s) mol_slice_by_offset(s, 9, 1)
mol_errno MolReader_UncleBlockVec_verify(const mol_seg_t *, bool);
#define MolReader_UncleBlockVec_length(s) mol_dynvec_length(s)
#define MolReader_UncleBlockVec_get(s, i) mol_dynvec_slice_by_index(s, i)
mol_errno MolReader_TransactionVec_verify(const mol_seg_t *, bool);
#define MolReader_TransactionVec_length(s) mol_dynvec_length(s)
#define MolReader_TransactionVec_get(s, i) mol_dynvec_slice_by_index(s, i)
#define MolReader_ProposalShortIdVec_verify(s, c) mol_fixvec_verify(s, 10)
#define MolReader_ProposalShortIdVec_length(s) mol_fixvec_length(s)
#define MolReader_ProposalShortIdVec_get(s, i) \
  mol_fixvec_slice_by_index(s, 10, i)
#define MolReader_CellDepVec_verify(s, c) mol_fixvec_verify(s, 37)
#define MolReader_CellDepVec_length(s) mol_fixvec_length(s)
#define MolReader_CellDepVec_get(s, i) mol_fixvec_slice_by_index(s, 37, i)
#define MolReader_CellInputVec_verify(s, c) mol_fixvec_verify(s, 44)
#define MolReader_CellInputVec_length(s) mol_fixvec_length(s)
#define MolReader_CellInputVec_get(s, i) mol_fixvec_slice_by_index(s, 44, i)
mol_errno MolReader_CellOutputVec_verify(const mol_seg_t *, bool);
#define MolReader_CellOutputVec_length(s) mol_dynvec_length(s)
#define MolReader_CellOutputVec_get(s, i) mol_dynvec_slice_by_index(s, i)
mol_errno MolReader_Script_verify(const mol_seg_t *, bool);
#define MolReader_Script_actual_field_count(s) mol_table_actual_field_count(s)
#define MolReader_Script_has_extra_fields(s) mol_table_has_extra_fields(s, 3)
#define MolReader_Script_get_code_hash(s) mol_table_slice_by_index(s, 0)
#define MolReader_Script_get_hash_type(s) mol_table_slice_by_index(s, 1)
#define MolReader_Script_get_args(s) mol_table_slice_by_index(s, 2)
#define MolReader_OutPoint_verify(s, c) mol_verify_fixed_size(s, 36)
#define MolReader_OutPoint_get_tx_hash(s) mol_slice_by_offset(s, 0, 32)
#define MolReader_OutPoint_get_index(s) mol_slice_by_offset(s, 32, 4)
#define MolReader_CellInput_verify(s, c) mol_verify_fixed_size(s, 44)
#define MolReader_CellInput_get_since(s) mol_slice_by_offset(s, 0, 8)
#define MolReader_CellInput_get_previous_output(s) mol_slice_by_offset(s, 8, 36)
mol_errno MolReader_CellOutput_verify(const mol_seg_t *, bool);
#define MolReader_CellOutput_actual_field_count(s) \
  mol_table_actual_field_count(s)
#define MolReader_CellOutput_has_extra_fields(s) \
  mol_table_has_extra_fields(s, 3)
#define MolReader_CellOutput_get_capacity(s) mol_table_slice_by_index(s, 0)
#define MolReader_CellOutput_get_lock(s) mol_table_slice_by_index(s, 1)
#define MolReader_CellOutput_get_type_(s) mol_table_slice_by_index(s, 2)
#define MolReader_CellDep_verify(s, c) mol_verify_fixed_size(s, 37)
#define MolReader_CellDep_get_out_point(s) mol_slice_by_offset(s, 0, 36)
#define MolReader_CellDep_get_dep_type(s) mol_slice_by_offset(s, 36, 1)
mol_errno MolReader_RawTransaction_verify(const mol_seg_t *, bool);
#define MolReader_RawTransaction_actual_field_count(s) \
  mol_table_actual_field_count(s)
#define MolReader_RawTransaction_has_extra_fields(s) \
  mol_table_has_extra_fields(s, 6)
#define MolReader_RawTransaction_get_version(s) mol_table_slice_by_index(s, 0)
#define MolReader_RawTransaction_get_cell_deps(s) mol_table_slice_by_index(s, 1)
#define MolReader_RawTransaction_get_header_deps(s) \
  mol_table_slice_by_index(s, 2)
#define MolReader_RawTransaction_get_inputs(s) mol_table_slice_by_index(s, 3)
#define MolReader_RawTransaction_get_outputs(s) mol_table_slice_by_index(s, 4)
#define MolReader_RawTransaction_get_outputs_data(s) \
  mol_table_slice_by_index(s, 5)
mol_errno MolReader_Transaction_verify(const mol_seg_t *, bool);
#define MolReader_Transaction_actual_field_count(s) \
  mol_table_actual_field_count(s)
#define MolReader_Transaction_has_extra_fields(s) \
  mol_table_has_extra_fields(s, 2)
#define MolReader_Transaction_get_raw(s) mol_table_slice_by_index(s, 0)
#define MolReader_Transaction_get_witnesses(s) mol_table_slice_by_index(s, 1)
#define MolReader_RawHeader_verify(s, c) mol_verify_fixed_size(s, 192)
#define MolReader_RawHeader_get_version(s) mol_slice_by_offset(s, 0, 4)
#define MolReader_RawHeader_get_compact_target(s) mol_slice_by_offset(s, 4, 4)
#define MolReader_RawHeader_get_timestamp(s) mol_slice_by_offset(s, 8, 8)
#define MolReader_RawHeader_get_number(s) mol_slice_by_offset(s, 16, 8)
#define MolReader_RawHeader_get_epoch(s) mol_slice_by_offset(s, 24, 8)
#define MolReader_RawHeader_get_parent_hash(s) mol_slice_by_offset(s, 32, 32)
#define MolReader_RawHeader_get_transactions_root(s) \
  mol_slice_by_offset(s, 64, 32)
#define MolReader_RawHeader_get_proposals_hash(s) mol_slice_by_offset(s, 96, 32)
#define MolReader_RawHeader_get_uncles_hash(s) mol_slice_by_offset(s, 128, 32)
#define MolReader_RawHeader_get_dao(s) mol_slice_by_offset(s, 160, 32)
#define MolReader_Header_verify(s, c) mol_verify_fixed_size(s, 208)
#define MolReader_Header_get_raw(s) mol_slice_by_offset(s, 0, 192)
#define MolReader_Header_get_nonce(s) mol_slice_by_offset(s, 192, 16)
mol_errno MolReader_UncleBlock_verify(const mol_seg_t *, bool);
#define MolReader_UncleBlock_actual_field_count(s) \
  mol_table_actual_field_count(s)
#define MolReader_UncleBlock_has_extra_fields(s) \
  mol_table_has_extra_fields(s, 2)
#define MolReader_UncleBlock_get_header(s) mol_table_slice_by_index(s, 0)
#define MolReader_UncleBlock_get_proposals(s) mol_table_slice_by_index(s, 1)
mol_errno MolReader_Block_verify(const mol_seg_t *, bool);
#define MolReader_Block_actual_field_count(s) mol_table_actual_field_count(s)
#define MolReader_Block_has_extra_fields(s) mol_table_has_extra_fields(s, 4)
#define MolReader_Block_get_header(s) mol_table_slice_by_index(s, 0)
#define MolReader_Block_get_uncles(s) mol_table_slice_by_index(s, 1)
#define MolReader_Block_get_transactions(s) mol_table_slice_by_index(s, 2)
#define MolReader_Block_get_proposals(s) mol_table_slice_by_index(s, 3)
mol_errno MolReader_CellbaseWitness_verify(const mol_seg_t *, bool);
#define MolReader_CellbaseWitness_actual_field_count(s) \
  mol_table_actual_field_count(s)
#define MolReader_CellbaseWitness_has_extra_fields(s) \
  mol_table_has_extra_fields(s, 2)
#define MolReader_CellbaseWitness_get_lock(s) mol_table_slice_by_index(s, 0)
#define MolReader_CellbaseWitness_get_message(s) mol_table_slice_by_index(s, 1)
mol_errno MolReader_WitnessArgs_verify(const mol_seg_t *, bool);
#define MolReader_WitnessArgs_actual_field_count(s) \
  mol_table_actual_field_count(s)
#define MolReader_WitnessArgs_has_extra_fields(s) \
  mol_table_has_extra_fields(s, 3)
#define MolReader_WitnessArgs_get_lock(s) mol_table_slice_by_index(s, 0)
#define MolReader_WitnessArgs_get_input_type(s) mol_table_slice_by_index(s, 1)
#define MolReader_WitnessArgs_get_output_type(s) mol_table_slice_by_index(s, 2)

/*
 * Builder APIs
 */

#define MolBuilder_Uint32_init(b) mol_builder_initialize_fixed_size(b, 4)
#define MolBuilder_Uint32_set_nth0(b, p) mol_builder_set_byte_by_offset(b, 0, p)
#define MolBuilder_Uint32_set_nth1(b, p) mol_builder_set_byte_by_offset(b, 1, p)
#define MolBuilder_Uint32_set_nth2(b, p) mol_builder_set_byte_by_offset(b, 2, p)
#define MolBuilder_Uint32_set_nth3(b, p) mol_builder_set_byte_by_offset(b, 3, p)
#define MolBuilder_Uint32_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_Uint32_clear(b) mol_builder_discard(b)
#define MolBuilder_Uint64_init(b) mol_builder_initialize_fixed_size(b, 8)
#define MolBuilder_Uint64_set_nth0(b, p) mol_builder_set_byte_by_offset(b, 0, p)
#define MolBuilder_Uint64_set_nth1(b, p) mol_builder_set_byte_by_offset(b, 1, p)
#define MolBuilder_Uint64_set_nth2(b, p) mol_builder_set_byte_by_offset(b, 2, p)
#define MolBuilder_Uint64_set_nth3(b, p) mol_builder_set_byte_by_offset(b, 3, p)
#define MolBuilder_Uint64_set_nth4(b, p) mol_builder_set_byte_by_offset(b, 4, p)
#define MolBuilder_Uint64_set_nth5(b, p) mol_builder_set_byte_by_offset(b, 5, p)
#define MolBuilder_Uint64_set_nth6(b, p) mol_builder_set_byte_by_offset(b, 6, p)
#define MolBuilder_Uint64_set_nth7(b, p) mol_builder_set_byte_by_offset(b, 7, p)
#define MolBuilder_Uint64_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_Uint64_clear(b) mol_builder_discard(b)
#define MolBuilder_Uint128_init(b) mol_builder_initialize_fixed_size(b, 16)
#define MolBuilder_Uint128_set_nth0(b, p) \
  mol_builder_set_byte_by_offset(b, 0, p)
#define MolBuilder_Uint128_set_nth1(b, p) \
  mol_builder_set_byte_by_offset(b, 1, p)
#define MolBuilder_Uint128_set_nth2(b, p) \
  mol_builder_set_byte_by_offset(b, 2, p)
#define MolBuilder_Uint128_set_nth3(b, p) \
  mol_builder_set_byte_by_offset(b, 3, p)
#define MolBuilder_Uint128_set_nth4(b, p) \
  mol_builder_set_byte_by_offset(b, 4, p)
#define MolBuilder_Uint128_set_nth5(b, p) \
  mol_builder_set_byte_by_offset(b, 5, p)
#define MolBuilder_Uint128_set_nth6(b, p) \
  mol_builder_set_byte_by_offset(b, 6, p)
#define MolBuilder_Uint128_set_nth7(b, p) \
  mol_builder_set_byte_by_offset(b, 7, p)
#define MolBuilder_Uint128_set_nth8(b, p) \
  mol_builder_set_byte_by_offset(b, 8, p)
#define MolBuilder_Uint128_set_nth9(b, p) \
  mol_builder_set_byte_by_offset(b, 9, p)
#define MolBuilder_Uint128_set_nth10(b, p) \
  mol_builder_set_byte_by_offset(b, 10, p)
#define MolBuilder_Uint128_set_nth11(b, p) \
  mol_builder_set_byte_by_offset(b, 11, p)
#define MolBuilder_Uint128_set_nth12(b, p) \
  mol_builder_set_byte_by_offset(b, 12, p)
#define MolBuilder_Uint128_set_nth13(b, p) \
  mol_builder_set_byte_by_offset(b, 13, p)
#define MolBuilder_Uint128_set_nth14(b, p) \
  mol_builder_set_byte_by_offset(b, 14, p)
#define MolBuilder_Uint128_set_nth15(b, p) \
  mol_builder_set_byte_by_offset(b, 15, p)
#define MolBuilder_Uint128_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_Uint128_clear(b) mol_builder_discard(b)
#define MolBuilder_Byte32_init(b) mol_builder_initialize_fixed_size(b, 32)
#define MolBuilder_Byte32_set_nth0(b, p) mol_builder_set_byte_by_offset(b, 0, p)
#define MolBuilder_Byte32_set_nth1(b, p) mol_builder_set_byte_by_offset(b, 1, p)
#define MolBuilder_Byte32_set_nth2(b, p) mol_builder_set_byte_by_offset(b, 2, p)
#define MolBuilder_Byte32_set_nth3(b, p) mol_builder_set_byte_by_offset(b, 3, p)
#define MolBuilder_Byte32_set_nth4(b, p) mol_builder_set_byte_by_offset(b, 4, p)
#define MolBuilder_Byte32_set_nth5(b, p) mol_builder_set_byte_by_offset(b, 5, p)
#define MolBuilder_Byte32_set_nth6(b, p) mol_builder_set_byte_by_offset(b, 6, p)
#define MolBuilder_Byte32_set_nth7(b, p) mol_builder_set_byte_by_offset(b, 7, p)
#define MolBuilder_Byte32_set_nth8(b, p) mol_builder_set_byte_by_offset(b, 8, p)
#define MolBuilder_Byte32_set_nth9(b, p) mol_builder_set_byte_by_offset(b, 9, p)
#define MolBuilder_Byte32_set_nth10(b, p) \
  mol_builder_set_byte_by_offset(b, 10, p)
#define MolBuilder_Byte32_set_nth11(b, p) \
  mol_builder_set_byte_by_offset(b, 11, p)
#define MolBuilder_Byte32_set_nth12(b, p) \
  mol_builder_set_byte_by_offset(b, 12, p)
#define MolBuilder_Byte32_set_nth13(b, p) \
  mol_builder_set_byte_by_offset(b, 13, p)
#define MolBuilder_Byte32_set_nth14(b, p) \
  mol_builder_set_byte_by_offset(b, 14, p)
#define MolBuilder_Byte32_set_nth15(b, p) \
  mol_builder_set_byte_by_offset(b, 15, p)
#define MolBuilder_Byte32_set_nth16(b, p) \
  mol_builder_set_byte_by_offset(b, 16, p)
#define MolBuilder_Byte32_set_nth17(b, p) \
  mol_builder_set_byte_by_offset(b, 17, p)
#define MolBuilder_Byte32_set_nth18(b, p) \
  mol_builder_set_byte_by_offset(b, 18, p)
#define MolBuilder_Byte32_set_nth19(b, p) \
  mol_builder_set_byte_by_offset(b, 19, p)
#define MolBuilder_Byte32_set_nth20(b, p) \
  mol_builder_set_byte_by_offset(b, 20, p)
#define MolBuilder_Byte32_set_nth21(b, p) \
  mol_builder_set_byte_by_offset(b, 21, p)
#define MolBuilder_Byte32_set_nth22(b, p) \
  mol_builder_set_byte_by_offset(b, 22, p)
#define MolBuilder_Byte32_set_nth23(b, p) \
  mol_builder_set_byte_by_offset(b, 23, p)
#define MolBuilder_Byte32_set_nth24(b, p) \
  mol_builder_set_byte_by_offset(b, 24, p)
#define MolBuilder_Byte32_set_nth25(b, p) \
  mol_builder_set_byte_by_offset(b, 25, p)
#define MolBuilder_Byte32_set_nth26(b, p) \
  mol_builder_set_byte_by_offset(b, 26, p)
#define MolBuilder_Byte32_set_nth27(b, p) \
  mol_builder_set_byte_by_offset(b, 27, p)
#define MolBuilder_Byte32_set_nth28(b, p) \
  mol_builder_set_byte_by_offset(b, 28, p)
#define MolBuilder_Byte32_set_nth29(b, p) \
  mol_builder_set_byte_by_offset(b, 29, p)
#define MolBuilder_Byte32_set_nth30(b, p) \
  mol_builder_set_byte_by_offset(b, 30, p)
#define MolBuilder_Byte32_set_nth31(b, p) \
  mol_builder_set_byte_by_offset(b, 31, p)
#define MolBuilder_Byte32_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_Byte32_clear(b) mol_builder_discard(b)
#define MolBuilder_Uint256_init(b) mol_builder_initialize_fixed_size(b, 32)
#define MolBuilder_Uint256_set_nth0(b, p) \
  mol_builder_set_byte_by_offset(b, 0, p)
#define MolBuilder_Uint256_set_nth1(b, p) \
  mol_builder_set_byte_by_offset(b, 1, p)
#define MolBuilder_Uint256_set_nth2(b, p) \
  mol_builder_set_byte_by_offset(b, 2, p)
#define MolBuilder_Uint256_set_nth3(b, p) \
  mol_builder_set_byte_by_offset(b, 3, p)
#define MolBuilder_Uint256_set_nth4(b, p) \
  mol_builder_set_byte_by_offset(b, 4, p)
#define MolBuilder_Uint256_set_nth5(b, p) \
  mol_builder_set_byte_by_offset(b, 5, p)
#define MolBuilder_Uint256_set_nth6(b, p) \
  mol_builder_set_byte_by_offset(b, 6, p)
#define MolBuilder_Uint256_set_nth7(b, p) \
  mol_builder_set_byte_by_offset(b, 7, p)
#define MolBuilder_Uint256_set_nth8(b, p) \
  mol_builder_set_byte_by_offset(b, 8, p)
#define MolBuilder_Uint256_set_nth9(b, p) \
  mol_builder_set_byte_by_offset(b, 9, p)
#define MolBuilder_Uint256_set_nth10(b, p) \
  mol_builder_set_byte_by_offset(b, 10, p)
#define MolBuilder_Uint256_set_nth11(b, p) \
  mol_builder_set_byte_by_offset(b, 11, p)
#define MolBuilder_Uint256_set_nth12(b, p) \
  mol_builder_set_byte_by_offset(b, 12, p)
#define MolBuilder_Uint256_set_nth13(b, p) \
  mol_builder_set_byte_by_offset(b, 13, p)
#define MolBuilder_Uint256_set_nth14(b, p) \
  mol_builder_set_byte_by_offset(b, 14, p)
#define MolBuilder_Uint256_set_nth15(b, p) \
  mol_builder_set_byte_by_offset(b, 15, p)
#define MolBuilder_Uint256_set_nth16(b, p) \
  mol_builder_set_byte_by_offset(b, 16, p)
#define MolBuilder_Uint256_set_nth17(b, p) \
  mol_builder_set_byte_by_offset(b, 17, p)
#define MolBuilder_Uint256_set_nth18(b, p) \
  mol_builder_set_byte_by_offset(b, 18, p)
#define MolBuilder_Uint256_set_nth19(b, p) \
  mol_builder_set_byte_by_offset(b, 19, p)
#define MolBuilder_Uint256_set_nth20(b, p) \
  mol_builder_set_byte_by_offset(b, 20, p)
#define MolBuilder_Uint256_set_nth21(b, p) \
  mol_builder_set_byte_by_offset(b, 21, p)
#define MolBuilder_Uint256_set_nth22(b, p) \
  mol_builder_set_byte_by_offset(b, 22, p)
#define MolBuilder_Uint256_set_nth23(b, p) \
  mol_builder_set_byte_by_offset(b, 23, p)
#define MolBuilder_Uint256_set_nth24(b, p) \
  mol_builder_set_byte_by_offset(b, 24, p)
#define MolBuilder_Uint256_set_nth25(b, p) \
  mol_builder_set_byte_by_offset(b, 25, p)
#define MolBuilder_Uint256_set_nth26(b, p) \
  mol_builder_set_byte_by_offset(b, 26, p)
#define MolBuilder_Uint256_set_nth27(b, p) \
  mol_builder_set_byte_by_offset(b, 27, p)
#define MolBuilder_Uint256_set_nth28(b, p) \
  mol_builder_set_byte_by_offset(b, 28, p)
#define MolBuilder_Uint256_set_nth29(b, p) \
  mol_builder_set_byte_by_offset(b, 29, p)
#define MolBuilder_Uint256_set_nth30(b, p) \
  mol_builder_set_byte_by_offset(b, 30, p)
#define MolBuilder_Uint256_set_nth31(b, p) \
  mol_builder_set_byte_by_offset(b, 31, p)
#define MolBuilder_Uint256_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_Uint256_clear(b) mol_builder_discard(b)
#define MolBuilder_Bytes_init(b) mol_fixvec_builder_initialize(b, 16)
#define MolBuilder_Bytes_push(b, p) mol_fixvec_builder_push_byte(b, p)
#define MolBuilder_Bytes_build(b) mol_fixvec_builder_finalize(b)
#define MolBuilder_Bytes_clear(b) mol_builder_discard(b)
#define MolBuilder_BytesOpt_init(b) mol_builder_initialize_fixed_size(b, 0)
#define MolBuilder_BytesOpt_set(b, p, l) mol_option_builder_set(b, p, l)
#define MolBuilder_BytesOpt_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_BytesOpt_clear(b) mol_builder_discard(b)
#define MolBuilder_BytesVec_init(b) \
  mol_builder_initialize_with_capacity(b, 64, 64)
#define MolBuilder_BytesVec_push(b, p, l) mol_dynvec_builder_push(b, p, l)
#define MolBuilder_BytesVec_build(b) mol_dynvec_builder_finalize(b)
#define MolBuilder_BytesVec_clear(b) mol_builder_discard(b)
#define MolBuilder_Byte32Vec_init(b) mol_fixvec_builder_initialize(b, 512)
#define MolBuilder_Byte32Vec_push(b, p) mol_fixvec_builder_push(b, p, 32)
#define MolBuilder_Byte32Vec_build(b) mol_fixvec_builder_finalize(b)
#define MolBuilder_Byte32Vec_clear(b) mol_builder_discard(b)
#define MolBuilder_ScriptOpt_init(b) mol_builder_initialize_fixed_size(b, 0)
#define MolBuilder_ScriptOpt_set(b, p, l) mol_option_builder_set(b, p, l)
#define MolBuilder_ScriptOpt_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_ScriptOpt_clear(b) mol_builder_discard(b)
#define MolBuilder_ProposalShortId_init(b) \
  mol_builder_initialize_fixed_size(b, 10)
#define MolBuilder_ProposalShortId_set_nth0(b, p) \
  mol_builder_set_byte_by_offset(b, 0, p)
#define MolBuilder_ProposalShortId_set_nth1(b, p) \
  mol_builder_set_byte_by_offset(b, 1, p)
#define MolBuilder_ProposalShortId_set_nth2(b, p) \
  mol_builder_set_byte_by_offset(b, 2, p)
#define MolBuilder_ProposalShortId_set_nth3(b, p) \
  mol_builder_set_byte_by_offset(b, 3, p)
#define MolBuilder_ProposalShortId_set_nth4(b, p) \
  mol_builder_set_byte_by_offset(b, 4, p)
#define MolBuilder_ProposalShortId_set_nth5(b, p) \
  mol_builder_set_byte_by_offset(b, 5, p)
#define MolBuilder_ProposalShortId_set_nth6(b, p) \
  mol_builder_set_byte_by_offset(b, 6, p)
#define MolBuilder_ProposalShortId_set_nth7(b, p) \
  mol_builder_set_byte_by_offset(b, 7, p)
#define MolBuilder_ProposalShortId_set_nth8(b, p) \
  mol_builder_set_byte_by_offset(b, 8, p)
#define MolBuilder_ProposalShortId_set_nth9(b, p) \
  mol_builder_set_byte_by_offset(b, 9, p)
#define MolBuilder_ProposalShortId_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_ProposalShortId_clear(b) mol_builder_discard(b)
#define MolBuilder_UncleBlockVec_init(b) \
  mol_builder_initialize_with_capacity(b, 4096, 64)
#define MolBuilder_UncleBlockVec_push(b, p, l) mol_dynvec_builder_push(b, p, l)
#define MolBuilder_UncleBlockVec_build(b) mol_dynvec_builder_finalize(b)
#define MolBuilder_UncleBlockVec_clear(b) mol_builder_discard(b)
#define MolBuilder_TransactionVec_init(b) \
  mol_builder_initialize_with_capacity(b, 2048, 64)
#define MolBuilder_TransactionVec_push(b, p, l) mol_dynvec_builder_push(b, p, l)
#define MolBuilder_TransactionVec_build(b) mol_dynvec_builder_finalize(b)
#define MolBuilder_TransactionVec_clear(b) mol_builder_discard(b)
#define MolBuilder_ProposalShortIdVec_init(b) \
  mol_fixvec_builder_initialize(b, 256)
#define MolBuilder_ProposalShortIdVec_push(b, p) \
  mol_fixvec_builder_push(b, p, 10)
#define MolBuilder_ProposalShortIdVec_build(b) mol_fixvec_builder_finalize(b)
#define MolBuilder_ProposalShortIdVec_clear(b) mol_builder_discard(b)
#define MolBuilder_CellDepVec_init(b) mol_fixvec_builder_initialize(b, 1024)
#define MolBuilder_CellDepVec_push(b, p) mol_fixvec_builder_push(b, p, 37)
#define MolBuilder_CellDepVec_build(b) mol_fixvec_builder_finalize(b)
#define MolBuilder_CellDepVec_clear(b) mol_builder_discard(b)
#define MolBuilder_CellInputVec_init(b) mol_fixvec_builder_initialize(b, 1024)
#define MolBuilder_CellInputVec_push(b, p) mol_fixvec_builder_push(b, p, 44)
#define MolBuilder_CellInputVec_build(b) mol_fixvec_builder_finalize(b)
#define MolBuilder_CellInputVec_clear(b) mol_builder_discard(b)
#define MolBuilder_CellOutputVec_init(b) \
  mol_builder_initialize_with_capacity(b, 2048, 64)
#define MolBuilder_CellOutputVec_push(b, p, l) mol_dynvec_builder_push(b, p, l)
#define MolBuilder_CellOutputVec_build(b) mol_dynvec_builder_finalize(b)
#define MolBuilder_CellOutputVec_clear(b) mol_builder_discard(b)
#define MolBuilder_Script_init(b) mol_table_builder_initialize(b, 256, 3)
#define MolBuilder_Script_set_code_hash(b, p, l) \
  mol_table_builder_add(b, 0, p, l)
#define MolBuilder_Script_set_hash_type(b, p) \
  mol_table_builder_add_byte(b, 1, p)
#define MolBuilder_Script_set_args(b, p, l) mol_table_builder_add(b, 2, p, l)
mol_seg_res_t MolBuilder_Script_build(mol_builder_t);
#define MolBuilder_Script_clear(b) mol_builder_discard(b)
#define MolBuilder_OutPoint_init(b) mol_builder_initialize_fixed_size(b, 36)
#define MolBuilder_OutPoint_set_tx_hash(b, p) \
  mol_builder_set_by_offset(b, 0, p, 32)
#define MolBuilder_OutPoint_set_index(b, p) \
  mol_builder_set_by_offset(b, 32, p, 4)
#define MolBuilder_OutPoint_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_OutPoint_clear(b) mol_builder_discard(b)
#define MolBuilder_CellInput_init(b) mol_builder_initialize_fixed_size(b, 44)
#define MolBuilder_CellInput_set_since(b, p) \
  mol_builder_set_by_offset(b, 0, p, 8)
#define MolBuilder_CellInput_set_previous_output(b, p) \
  mol_builder_set_by_offset(b, 8, p, 36)
#define MolBuilder_CellInput_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_CellInput_clear(b) mol_builder_discard(b)
#define MolBuilder_CellOutput_init(b) mol_table_builder_initialize(b, 512, 3)
#define MolBuilder_CellOutput_set_capacity(b, p, l) \
  mol_table_builder_add(b, 0, p, l)
#define MolBuilder_CellOutput_set_lock(b, p, l) \
  mol_table_builder_add(b, 1, p, l)
#define MolBuilder_CellOutput_set_type_(b, p, l) \
  mol_table_builder_add(b, 2, p, l)
mol_seg_res_t MolBuilder_CellOutput_build(mol_builder_t);
#define MolBuilder_CellOutput_clear(b) mol_builder_discard(b)
#define MolBuilder_CellDep_init(b) mol_builder_initialize_fixed_size(b, 37)
#define MolBuilder_CellDep_set_out_point(b, p) \
  mol_builder_set_by_offset(b, 0, p, 36)
#define MolBuilder_CellDep_set_dep_type(b, p) \
  mol_builder_set_byte_by_offset(b, 36, p)
#define MolBuilder_CellDep_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_CellDep_clear(b) mol_builder_discard(b)
#define MolBuilder_RawTransaction_init(b) \
  mol_table_builder_initialize(b, 256, 6)
#define MolBuilder_RawTransaction_set_version(b, p, l) \
  mol_table_builder_add(b, 0, p, l)
#define MolBuilder_RawTransaction_set_cell_deps(b, p, l) \
  mol_table_builder_add(b, 1, p, l)
#define MolBuilder_RawTransaction_set_header_deps(b, p, l) \
  mol_table_builder_add(b, 2, p, l)
#define MolBuilder_RawTransaction_set_inputs(b, p, l) \
  mol_table_builder_add(b, 3, p, l)
#define MolBuilder_RawTransaction_set_outputs(b, p, l) \
  mol_table_builder_add(b, 4, p, l)
#define MolBuilder_RawTransaction_set_outputs_data(b, p, l) \
  mol_table_builder_add(b, 5, p, l)
mol_seg_res_t MolBuilder_RawTransaction_build(mol_builder_t);
#define MolBuilder_RawTransaction_clear(b) mol_builder_discard(b)
#define MolBuilder_Transaction_init(b) mol_table_builder_initialize(b, 512, 2)
#define MolBuilder_Transaction_set_raw(b, p, l) \
  mol_table_builder_add(b, 0, p, l)
#define MolBuilder_Transaction_set_witnesses(b, p, l) \
  mol_table_builder_add(b, 1, p, l)
mol_seg_res_t MolBuilder_Transaction_build(mol_builder_t);
#define MolBuilder_Transaction_clear(b) mol_builder_discard(b)
#define MolBuilder_RawHeader_init(b) mol_builder_initialize_fixed_size(b, 192)
#define MolBuilder_RawHeader_set_version(b, p) \
  mol_builder_set_by_offset(b, 0, p, 4)
#define MolBuilder_RawHeader_set_compact_target(b, p) \
  mol_builder_set_by_offset(b, 4, p, 4)
#define MolBuilder_RawHeader_set_timestamp(b, p) \
  mol_builder_set_by_offset(b, 8, p, 8)
#define MolBuilder_RawHeader_set_number(b, p) \
  mol_builder_set_by_offset(b, 16, p, 8)
#define MolBuilder_RawHeader_set_epoch(b, p) \
  mol_builder_set_by_offset(b, 24, p, 8)
#define MolBuilder_RawHeader_set_parent_hash(b, p) \
  mol_builder_set_by_offset(b, 32, p, 32)
#define MolBuilder_RawHeader_set_transactions_root(b, p) \
  mol_builder_set_by_offset(b, 64, p, 32)
#define MolBuilder_RawHeader_set_proposals_hash(b, p) \
  mol_builder_set_by_offset(b, 96, p, 32)
#define MolBuilder_RawHeader_set_uncles_hash(b, p) \
  mol_builder_set_by_offset(b, 128, p, 32)
#define MolBuilder_RawHeader_set_dao(b, p) \
  mol_builder_set_by_offset(b, 160, p, 32)
#define MolBuilder_RawHeader_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_RawHeader_clear(b) mol_builder_discard(b)
#define MolBuilder_Header_init(b) mol_builder_initialize_fixed_size(b, 208)
#define MolBuilder_Header_set_raw(b, p) mol_builder_set_by_offset(b, 0, p, 192)
#define MolBuilder_Header_set_nonce(b, p) \
  mol_builder_set_by_offset(b, 192, p, 16)
#define MolBuilder_Header_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_Header_clear(b) mol_builder_discard(b)
#define MolBuilder_UncleBlock_init(b) mol_table_builder_initialize(b, 1024, 2)
#define MolBuilder_UncleBlock_set_header(b, p, l) \
  mol_table_builder_add(b, 0, p, l)
#define MolBuilder_UncleBlock_set_proposals(b, p, l) \
  mol_table_builder_add(b, 1, p, l)
mol_seg_res_t MolBuilder_UncleBlock_build(mol_builder_t);
#define MolBuilder_UncleBlock_clear(b) mol_builder_discard(b)
#define MolBuilder_Block_init(b) mol_table_builder_initialize(b, 1024, 4)
#define MolBuilder_Block_set_header(b, p, l) mol_table_builder_add(b, 0, p, l)
#define MolBuilder_Block_set_uncles(b, p, l) mol_table_builder_add(b, 1, p, l)
#define MolBuilder_Block_set_transactions(b, p, l) \
  mol_table_builder_add(b, 2, p, l)
#define MolBuilder_Block_set_proposals(b, p, l) \
  mol_table_builder_add(b, 3, p, l)
mol_seg_res_t MolBuilder_Block_build(mol_builder_t);
#define MolBuilder_Block_clear(b) mol_builder_discard(b)
#define MolBuilder_CellbaseWitness_init(b) \
  mol_table_builder_initialize(b, 512, 2)
#define MolBuilder_CellbaseWitness_set_lock(b, p, l) \
  mol_table_builder_add(b, 0, p, l)
#define MolBuilder_CellbaseWitness_set_message(b, p, l) \
  mol_table_builder_add(b, 1, p, l)
mol_seg_res_t MolBuilder_CellbaseWitness_build(mol_builder_t);
#define MolBuilder_CellbaseWitness_clear(b) mol_builder_discard(b)
#define MolBuilder_WitnessArgs_init(b) mol_table_builder_initialize(b, 64, 3)
#define MolBuilder_WitnessArgs_set_lock(b, p, l) \
  mol_table_builder_add(b, 0, p, l)
#define MolBuilder_WitnessArgs_set_input_type(b, p, l) \
  mol_table_builder_add(b, 1, p, l)
#define MolBuilder_WitnessArgs_set_output_type(b, p, l) \
  mol_table_builder_add(b, 2, p, l)
mol_seg_res_t MolBuilder_WitnessArgs_build(mol_builder_t);
#define MolBuilder_WitnessArgs_clear(b) mol_builder_discard(b)

#endif //CKB_MISCELLANEOUS_SCRIPTS_SIMULATOR_MOLECULE_DECL_ONLY_H_
