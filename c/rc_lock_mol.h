// Generated by Molecule 0.7.0

#define MOLECULEC_VERSION 7000
#define MOLECULE_API_VERSION_MIN 7000

#include "molecule_builder.h"
#include "molecule_reader.h"

#ifndef RC_LOCK_H
#define RC_LOCK_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef MOLECULE_API_DECORATOR
#define __DEFINE_MOLECULE_API_DECORATOR_RC_LOCK
#define MOLECULE_API_DECORATOR
#endif /* MOLECULE_API_DECORATOR */

#include "blockchain.h"

/*
 * Reader APIs
 */

#define MolReader_Identity_verify(s, c) mol_verify_fixed_size(s, 21)
#define MolReader_Identity_get_nth0(s) mol_slice_by_offset(s, 0, 1)
#define MolReader_Identity_get_nth1(s) mol_slice_by_offset(s, 1, 1)
#define MolReader_Identity_get_nth2(s) mol_slice_by_offset(s, 2, 1)
#define MolReader_Identity_get_nth3(s) mol_slice_by_offset(s, 3, 1)
#define MolReader_Identity_get_nth4(s) mol_slice_by_offset(s, 4, 1)
#define MolReader_Identity_get_nth5(s) mol_slice_by_offset(s, 5, 1)
#define MolReader_Identity_get_nth6(s) mol_slice_by_offset(s, 6, 1)
#define MolReader_Identity_get_nth7(s) mol_slice_by_offset(s, 7, 1)
#define MolReader_Identity_get_nth8(s) mol_slice_by_offset(s, 8, 1)
#define MolReader_Identity_get_nth9(s) mol_slice_by_offset(s, 9, 1)
#define MolReader_Identity_get_nth10(s) mol_slice_by_offset(s, 10, 1)
#define MolReader_Identity_get_nth11(s) mol_slice_by_offset(s, 11, 1)
#define MolReader_Identity_get_nth12(s) mol_slice_by_offset(s, 12, 1)
#define MolReader_Identity_get_nth13(s) mol_slice_by_offset(s, 13, 1)
#define MolReader_Identity_get_nth14(s) mol_slice_by_offset(s, 14, 1)
#define MolReader_Identity_get_nth15(s) mol_slice_by_offset(s, 15, 1)
#define MolReader_Identity_get_nth16(s) mol_slice_by_offset(s, 16, 1)
#define MolReader_Identity_get_nth17(s) mol_slice_by_offset(s, 17, 1)
#define MolReader_Identity_get_nth18(s) mol_slice_by_offset(s, 18, 1)
#define MolReader_Identity_get_nth19(s) mol_slice_by_offset(s, 19, 1)
#define MolReader_Identity_get_nth20(s) mol_slice_by_offset(s, 20, 1)
#define MolReader_SmtProof_verify(s, c) mol_fixvec_verify(s, 1)
#define MolReader_SmtProof_length(s) mol_fixvec_length(s)
#define MolReader_SmtProof_get(s, i) mol_fixvec_slice_by_index(s, 1, i)
#define MolReader_SmtProof_raw_bytes(s) mol_fixvec_slice_raw_bytes(s)
MOLECULE_API_DECORATOR mol_errno
MolReader_SmtProofEntry_verify(const mol_seg_t *, bool);
#define MolReader_SmtProofEntry_actual_field_count(s) \
  mol_table_actual_field_count(s)
#define MolReader_SmtProofEntry_has_extra_fields(s) \
  mol_table_has_extra_fields(s, 2)
#define MolReader_SmtProofEntry_get_mask(s) mol_table_slice_by_index(s, 0)
#define MolReader_SmtProofEntry_get_proof(s) mol_table_slice_by_index(s, 1)
MOLECULE_API_DECORATOR mol_errno
MolReader_SmtProofEntryVec_verify(const mol_seg_t *, bool);
#define MolReader_SmtProofEntryVec_length(s) mol_dynvec_length(s)
#define MolReader_SmtProofEntryVec_get(s, i) mol_dynvec_slice_by_index(s, i)
MOLECULE_API_DECORATOR mol_errno MolReader_RcIdentity_verify(const mol_seg_t *,
                                                             bool);
#define MolReader_RcIdentity_actual_field_count(s) \
  mol_table_actual_field_count(s)
#define MolReader_RcIdentity_has_extra_fields(s) \
  mol_table_has_extra_fields(s, 2)
#define MolReader_RcIdentity_get_identity(s) mol_table_slice_by_index(s, 0)
#define MolReader_RcIdentity_get_proofs(s) mol_table_slice_by_index(s, 1)
MOLECULE_API_DECORATOR mol_errno
MolReader_RcIdentityOpt_verify(const mol_seg_t *, bool);
#define MolReader_RcIdentityOpt_is_none(s) mol_option_is_none(s)
MOLECULE_API_DECORATOR mol_errno
MolReader_RcLockWitnessLock_verify(const mol_seg_t *, bool);
#define MolReader_RcLockWitnessLock_actual_field_count(s) \
  mol_table_actual_field_count(s)
#define MolReader_RcLockWitnessLock_has_extra_fields(s) \
  mol_table_has_extra_fields(s, 2)
#define MolReader_RcLockWitnessLock_get_signature(s) \
  mol_table_slice_by_index(s, 0)
#define MolReader_RcLockWitnessLock_get_rc_identity(s) \
  mol_table_slice_by_index(s, 1)

/*
 * Builder APIs
 */

#define MolBuilder_Identity_init(b) mol_builder_initialize_fixed_size(b, 21)
#define MolBuilder_Identity_set_nth0(b, p) \
  mol_builder_set_byte_by_offset(b, 0, p)
#define MolBuilder_Identity_set_nth1(b, p) \
  mol_builder_set_byte_by_offset(b, 1, p)
#define MolBuilder_Identity_set_nth2(b, p) \
  mol_builder_set_byte_by_offset(b, 2, p)
#define MolBuilder_Identity_set_nth3(b, p) \
  mol_builder_set_byte_by_offset(b, 3, p)
#define MolBuilder_Identity_set_nth4(b, p) \
  mol_builder_set_byte_by_offset(b, 4, p)
#define MolBuilder_Identity_set_nth5(b, p) \
  mol_builder_set_byte_by_offset(b, 5, p)
#define MolBuilder_Identity_set_nth6(b, p) \
  mol_builder_set_byte_by_offset(b, 6, p)
#define MolBuilder_Identity_set_nth7(b, p) \
  mol_builder_set_byte_by_offset(b, 7, p)
#define MolBuilder_Identity_set_nth8(b, p) \
  mol_builder_set_byte_by_offset(b, 8, p)
#define MolBuilder_Identity_set_nth9(b, p) \
  mol_builder_set_byte_by_offset(b, 9, p)
#define MolBuilder_Identity_set_nth10(b, p) \
  mol_builder_set_byte_by_offset(b, 10, p)
#define MolBuilder_Identity_set_nth11(b, p) \
  mol_builder_set_byte_by_offset(b, 11, p)
#define MolBuilder_Identity_set_nth12(b, p) \
  mol_builder_set_byte_by_offset(b, 12, p)
#define MolBuilder_Identity_set_nth13(b, p) \
  mol_builder_set_byte_by_offset(b, 13, p)
#define MolBuilder_Identity_set_nth14(b, p) \
  mol_builder_set_byte_by_offset(b, 14, p)
#define MolBuilder_Identity_set_nth15(b, p) \
  mol_builder_set_byte_by_offset(b, 15, p)
#define MolBuilder_Identity_set_nth16(b, p) \
  mol_builder_set_byte_by_offset(b, 16, p)
#define MolBuilder_Identity_set_nth17(b, p) \
  mol_builder_set_byte_by_offset(b, 17, p)
#define MolBuilder_Identity_set_nth18(b, p) \
  mol_builder_set_byte_by_offset(b, 18, p)
#define MolBuilder_Identity_set_nth19(b, p) \
  mol_builder_set_byte_by_offset(b, 19, p)
#define MolBuilder_Identity_set_nth20(b, p) \
  mol_builder_set_byte_by_offset(b, 20, p)
#define MolBuilder_Identity_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_Identity_clear(b) mol_builder_discard(b)
#define MolBuilder_SmtProof_init(b) mol_fixvec_builder_initialize(b, 16)
#define MolBuilder_SmtProof_push(b, p) mol_fixvec_builder_push_byte(b, p)
#define MolBuilder_SmtProof_build(b) mol_fixvec_builder_finalize(b)
#define MolBuilder_SmtProof_clear(b) mol_builder_discard(b)
#define MolBuilder_SmtProofEntry_init(b) mol_table_builder_initialize(b, 128, 2)
#define MolBuilder_SmtProofEntry_set_mask(b, p) \
  mol_table_builder_add_byte(b, 0, p)
#define MolBuilder_SmtProofEntry_set_proof(b, p, l) \
  mol_table_builder_add(b, 1, p, l)
MOLECULE_API_DECORATOR mol_seg_res_t
    MolBuilder_SmtProofEntry_build(mol_builder_t);
#define MolBuilder_SmtProofEntry_clear(b) mol_builder_discard(b)
#define MolBuilder_SmtProofEntryVec_init(b) \
  mol_builder_initialize_with_capacity(b, 512, 64)
#define MolBuilder_SmtProofEntryVec_push(b, p, l) \
  mol_dynvec_builder_push(b, p, l)
#define MolBuilder_SmtProofEntryVec_build(b) mol_dynvec_builder_finalize(b)
#define MolBuilder_SmtProofEntryVec_clear(b) mol_builder_discard(b)
#define MolBuilder_RcIdentity_init(b) mol_table_builder_initialize(b, 256, 2)
#define MolBuilder_RcIdentity_set_identity(b, p, l) \
  mol_table_builder_add(b, 0, p, l)
#define MolBuilder_RcIdentity_set_proofs(b, p, l) \
  mol_table_builder_add(b, 1, p, l)
MOLECULE_API_DECORATOR mol_seg_res_t MolBuilder_RcIdentity_build(mol_builder_t);
#define MolBuilder_RcIdentity_clear(b) mol_builder_discard(b)
#define MolBuilder_RcIdentityOpt_init(b) mol_builder_initialize_fixed_size(b, 0)
#define MolBuilder_RcIdentityOpt_set(b, p, l) mol_option_builder_set(b, p, l)
#define MolBuilder_RcIdentityOpt_build(b) mol_builder_finalize_simple(b)
#define MolBuilder_RcIdentityOpt_clear(b) mol_builder_discard(b)
#define MolBuilder_RcLockWitnessLock_init(b) \
  mol_table_builder_initialize(b, 64, 2)
#define MolBuilder_RcLockWitnessLock_set_signature(b, p, l) \
  mol_table_builder_add(b, 0, p, l)
#define MolBuilder_RcLockWitnessLock_set_rc_identity(b, p, l) \
  mol_table_builder_add(b, 1, p, l)
MOLECULE_API_DECORATOR mol_seg_res_t
    MolBuilder_RcLockWitnessLock_build(mol_builder_t);
#define MolBuilder_RcLockWitnessLock_clear(b) mol_builder_discard(b)

/*
 * Default Value
 */

#define ____ 0x00

MOLECULE_API_DECORATOR const uint8_t MolDefault_Identity[21] = {
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_SmtProof[4] = {____, ____, ____,
                                                               ____};
MOLECULE_API_DECORATOR const uint8_t MolDefault_SmtProofEntry[17] = {
    0x11, ____, ____, ____, 0x0c, ____, ____, ____, 0x0d,
    ____, ____, ____, ____, ____, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_SmtProofEntryVec[4] = {
    0x04, ____, ____, ____};
MOLECULE_API_DECORATOR const uint8_t MolDefault_RcIdentity[37] = {
    0x25, ____, ____, ____, 0x0c, ____, ____, ____, 0x21, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, 0x04, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_RcIdentityOpt[0] = {};
MOLECULE_API_DECORATOR const uint8_t MolDefault_RcLockWitnessLock[12] = {
    0x0c, ____, ____, ____, 0x0c, ____, ____, ____, 0x0c, ____, ____, ____,
};

#undef ____

/*
 * Reader Functions
 */

MOLECULE_API_DECORATOR mol_errno
MolReader_SmtProofEntry_verify(const mol_seg_t *input, bool compatible) {
  if (input->size < MOL_NUM_T_SIZE) {
    return MOL_ERR_HEADER;
  }
  uint8_t *ptr = input->ptr;
  mol_num_t total_size = mol_unpack_number(ptr);
  if (input->size != total_size) {
    return MOL_ERR_TOTAL_SIZE;
  }
  if (input->size < MOL_NUM_T_SIZE * 2) {
    return MOL_ERR_HEADER;
  }
  ptr += MOL_NUM_T_SIZE;
  mol_num_t offset = mol_unpack_number(ptr);
  if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE * 2) {
    return MOL_ERR_OFFSET;
  }
  mol_num_t field_count = offset / 4 - 1;
  if (field_count < 2) {
    return MOL_ERR_FIELD_COUNT;
  } else if (!compatible && field_count > 2) {
    return MOL_ERR_FIELD_COUNT;
  }
  if (input->size < MOL_NUM_T_SIZE * (field_count + 1)) {
    return MOL_ERR_HEADER;
  }
  mol_num_t offsets[field_count + 1];
  offsets[0] = offset;
  for (mol_num_t i = 1; i < field_count; i++) {
    ptr += MOL_NUM_T_SIZE;
    offsets[i] = mol_unpack_number(ptr);
    if (offsets[i - 1] > offsets[i]) {
      return MOL_ERR_OFFSET;
    }
  }
  if (offsets[field_count - 1] > total_size) {
    return MOL_ERR_OFFSET;
  }
  offsets[field_count] = total_size;
  mol_seg_t inner;
  mol_errno errno;
  if (offsets[1] - offsets[0] != 1) {
    return MOL_ERR_DATA;
  }
  inner.ptr = input->ptr + offsets[1];
  inner.size = offsets[2] - offsets[1];
  errno = MolReader_SmtProof_verify(&inner, compatible);
  if (errno != MOL_OK) {
    return MOL_ERR_DATA;
  }
  return MOL_OK;
}
MOLECULE_API_DECORATOR mol_errno
MolReader_SmtProofEntryVec_verify(const mol_seg_t *input, bool compatible) {
  if (input->size < MOL_NUM_T_SIZE) {
    return MOL_ERR_HEADER;
  }
  uint8_t *ptr = input->ptr;
  mol_num_t total_size = mol_unpack_number(ptr);
  if (input->size != total_size) {
    return MOL_ERR_TOTAL_SIZE;
  }
  if (input->size == MOL_NUM_T_SIZE) {
    return MOL_OK;
  }
  if (input->size < MOL_NUM_T_SIZE * 2) {
    return MOL_ERR_HEADER;
  }
  ptr += MOL_NUM_T_SIZE;
  mol_num_t offset = mol_unpack_number(ptr);
  if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE * 2) {
    return MOL_ERR_OFFSET;
  }
  mol_num_t item_count = offset / 4 - 1;
  if (input->size < MOL_NUM_T_SIZE * (item_count + 1)) {
    return MOL_ERR_HEADER;
  }
  mol_num_t end;
  for (mol_num_t i = 1; i < item_count; i++) {
    ptr += MOL_NUM_T_SIZE;
    end = mol_unpack_number(ptr);
    if (offset > end) {
      return MOL_ERR_OFFSET;
    }
    mol_seg_t inner;
    inner.ptr = input->ptr + offset;
    inner.size = end - offset;
    mol_errno errno = MolReader_SmtProofEntry_verify(&inner, compatible);
    if (errno != MOL_OK) {
      return MOL_ERR_DATA;
    }
    offset = end;
  }
  if (offset > total_size) {
    return MOL_ERR_OFFSET;
  }
  mol_seg_t inner;
  inner.ptr = input->ptr + offset;
  inner.size = total_size - offset;
  return MolReader_SmtProofEntry_verify(&inner, compatible);
}
MOLECULE_API_DECORATOR mol_errno
MolReader_RcIdentity_verify(const mol_seg_t *input, bool compatible) {
  if (input->size < MOL_NUM_T_SIZE) {
    return MOL_ERR_HEADER;
  }
  uint8_t *ptr = input->ptr;
  mol_num_t total_size = mol_unpack_number(ptr);
  if (input->size != total_size) {
    return MOL_ERR_TOTAL_SIZE;
  }
  if (input->size < MOL_NUM_T_SIZE * 2) {
    return MOL_ERR_HEADER;
  }
  ptr += MOL_NUM_T_SIZE;
  mol_num_t offset = mol_unpack_number(ptr);
  if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE * 2) {
    return MOL_ERR_OFFSET;
  }
  mol_num_t field_count = offset / 4 - 1;
  if (field_count < 2) {
    return MOL_ERR_FIELD_COUNT;
  } else if (!compatible && field_count > 2) {
    return MOL_ERR_FIELD_COUNT;
  }
  if (input->size < MOL_NUM_T_SIZE * (field_count + 1)) {
    return MOL_ERR_HEADER;
  }
  mol_num_t offsets[field_count + 1];
  offsets[0] = offset;
  for (mol_num_t i = 1; i < field_count; i++) {
    ptr += MOL_NUM_T_SIZE;
    offsets[i] = mol_unpack_number(ptr);
    if (offsets[i - 1] > offsets[i]) {
      return MOL_ERR_OFFSET;
    }
  }
  if (offsets[field_count - 1] > total_size) {
    return MOL_ERR_OFFSET;
  }
  offsets[field_count] = total_size;
  mol_seg_t inner;
  mol_errno errno;
  inner.ptr = input->ptr + offsets[0];
  inner.size = offsets[1] - offsets[0];
  errno = MolReader_Identity_verify(&inner, compatible);
  if (errno != MOL_OK) {
    return MOL_ERR_DATA;
  }
  inner.ptr = input->ptr + offsets[1];
  inner.size = offsets[2] - offsets[1];
  errno = MolReader_SmtProofEntryVec_verify(&inner, compatible);
  if (errno != MOL_OK) {
    return MOL_ERR_DATA;
  }
  return MOL_OK;
}
MOLECULE_API_DECORATOR mol_errno
MolReader_RcIdentityOpt_verify(const mol_seg_t *input, bool compatible) {
  if (input->size != 0) {
    return MolReader_RcIdentity_verify(input, compatible);
  } else {
    return MOL_OK;
  }
}
MOLECULE_API_DECORATOR mol_errno
MolReader_RcLockWitnessLock_verify(const mol_seg_t *input, bool compatible) {
  if (input->size < MOL_NUM_T_SIZE) {
    return MOL_ERR_HEADER;
  }
  uint8_t *ptr = input->ptr;
  mol_num_t total_size = mol_unpack_number(ptr);
  if (input->size != total_size) {
    return MOL_ERR_TOTAL_SIZE;
  }
  if (input->size < MOL_NUM_T_SIZE * 2) {
    return MOL_ERR_HEADER;
  }
  ptr += MOL_NUM_T_SIZE;
  mol_num_t offset = mol_unpack_number(ptr);
  if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE * 2) {
    return MOL_ERR_OFFSET;
  }
  mol_num_t field_count = offset / 4 - 1;
  if (field_count < 2) {
    return MOL_ERR_FIELD_COUNT;
  } else if (!compatible && field_count > 2) {
    return MOL_ERR_FIELD_COUNT;
  }
  if (input->size < MOL_NUM_T_SIZE * (field_count + 1)) {
    return MOL_ERR_HEADER;
  }
  mol_num_t offsets[field_count + 1];
  offsets[0] = offset;
  for (mol_num_t i = 1; i < field_count; i++) {
    ptr += MOL_NUM_T_SIZE;
    offsets[i] = mol_unpack_number(ptr);
    if (offsets[i - 1] > offsets[i]) {
      return MOL_ERR_OFFSET;
    }
  }
  if (offsets[field_count - 1] > total_size) {
    return MOL_ERR_OFFSET;
  }
  offsets[field_count] = total_size;
  mol_seg_t inner;
  mol_errno errno;
  inner.ptr = input->ptr + offsets[0];
  inner.size = offsets[1] - offsets[0];
  errno = MolReader_BytesOpt_verify(&inner, compatible);
  if (errno != MOL_OK) {
    return MOL_ERR_DATA;
  }
  inner.ptr = input->ptr + offsets[1];
  inner.size = offsets[2] - offsets[1];
  errno = MolReader_RcIdentityOpt_verify(&inner, compatible);
  if (errno != MOL_OK) {
    return MOL_ERR_DATA;
  }
  return MOL_OK;
}

/*
 * Builder Functions
 */

MOLECULE_API_DECORATOR mol_seg_res_t
MolBuilder_SmtProofEntry_build(mol_builder_t builder) {
  mol_seg_res_t res;
  res.errno = MOL_OK;
  mol_num_t offset = 12;
  mol_num_t len;
  res.seg.size = offset;
  len = builder.number_ptr[1];
  res.seg.size += len == 0 ? 1 : len;
  len = builder.number_ptr[3];
  res.seg.size += len == 0 ? 4 : len;
  res.seg.ptr = (uint8_t *)malloc(res.seg.size);
  uint8_t *dst = res.seg.ptr;
  mol_pack_number(dst, &res.seg.size);
  dst += MOL_NUM_T_SIZE;
  mol_pack_number(dst, &offset);
  dst += MOL_NUM_T_SIZE;
  len = builder.number_ptr[1];
  offset += len == 0 ? 1 : len;
  mol_pack_number(dst, &offset);
  dst += MOL_NUM_T_SIZE;
  len = builder.number_ptr[3];
  offset += len == 0 ? 4 : len;
  uint8_t *src = builder.data_ptr;
  len = builder.number_ptr[1];
  if (len == 0) {
    len = 1;
    *dst = 0;
  } else {
    mol_num_t of = builder.number_ptr[0];
    memcpy(dst, src + of, len);
  }
  dst += len;
  len = builder.number_ptr[3];
  if (len == 0) {
    len = 4;
    memcpy(dst, &MolDefault_SmtProof, len);
  } else {
    mol_num_t of = builder.number_ptr[2];
    memcpy(dst, src + of, len);
  }
  dst += len;
  mol_builder_discard(builder);
  return res;
}
MOLECULE_API_DECORATOR mol_seg_res_t
MolBuilder_RcIdentity_build(mol_builder_t builder) {
  mol_seg_res_t res;
  res.errno = MOL_OK;
  mol_num_t offset = 12;
  mol_num_t len;
  res.seg.size = offset;
  len = builder.number_ptr[1];
  res.seg.size += len == 0 ? 21 : len;
  len = builder.number_ptr[3];
  res.seg.size += len == 0 ? 4 : len;
  res.seg.ptr = (uint8_t *)malloc(res.seg.size);
  uint8_t *dst = res.seg.ptr;
  mol_pack_number(dst, &res.seg.size);
  dst += MOL_NUM_T_SIZE;
  mol_pack_number(dst, &offset);
  dst += MOL_NUM_T_SIZE;
  len = builder.number_ptr[1];
  offset += len == 0 ? 21 : len;
  mol_pack_number(dst, &offset);
  dst += MOL_NUM_T_SIZE;
  len = builder.number_ptr[3];
  offset += len == 0 ? 4 : len;
  uint8_t *src = builder.data_ptr;
  len = builder.number_ptr[1];
  if (len == 0) {
    len = 21;
    memcpy(dst, &MolDefault_Identity, len);
  } else {
    mol_num_t of = builder.number_ptr[0];
    memcpy(dst, src + of, len);
  }
  dst += len;
  len = builder.number_ptr[3];
  if (len == 0) {
    len = 4;
    memcpy(dst, &MolDefault_SmtProofEntryVec, len);
  } else {
    mol_num_t of = builder.number_ptr[2];
    memcpy(dst, src + of, len);
  }
  dst += len;
  mol_builder_discard(builder);
  return res;
}
MOLECULE_API_DECORATOR mol_seg_res_t
MolBuilder_RcLockWitnessLock_build(mol_builder_t builder) {
  mol_seg_res_t res;
  res.errno = MOL_OK;
  mol_num_t offset = 12;
  mol_num_t len;
  res.seg.size = offset;
  len = builder.number_ptr[1];
  res.seg.size += len == 0 ? 0 : len;
  len = builder.number_ptr[3];
  res.seg.size += len == 0 ? 0 : len;
  res.seg.ptr = (uint8_t *)malloc(res.seg.size);
  uint8_t *dst = res.seg.ptr;
  mol_pack_number(dst, &res.seg.size);
  dst += MOL_NUM_T_SIZE;
  mol_pack_number(dst, &offset);
  dst += MOL_NUM_T_SIZE;
  len = builder.number_ptr[1];
  offset += len == 0 ? 0 : len;
  mol_pack_number(dst, &offset);
  dst += MOL_NUM_T_SIZE;
  len = builder.number_ptr[3];
  offset += len == 0 ? 0 : len;
  uint8_t *src = builder.data_ptr;
  len = builder.number_ptr[1];
  if (len == 0) {
    len = 0;
    memcpy(dst, &MolDefault_BytesOpt, len);
  } else {
    mol_num_t of = builder.number_ptr[0];
    memcpy(dst, src + of, len);
  }
  dst += len;
  len = builder.number_ptr[3];
  if (len == 0) {
    len = 0;
    memcpy(dst, &MolDefault_RcIdentityOpt, len);
  } else {
    mol_num_t of = builder.number_ptr[2];
    memcpy(dst, src + of, len);
  }
  dst += len;
  mol_builder_discard(builder);
  return res;
}

#ifdef __DEFINE_MOLECULE_API_DECORATOR_RC_LOCK
#undef MOLECULE_API_DECORATOR
#undef __DEFINE_MOLECULE_API_DECORATOR_RC_LOCK
#endif /* __DEFINE_MOLECULE_API_DECORATOR_RC_LOCK */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* RC_LOCK_H */
