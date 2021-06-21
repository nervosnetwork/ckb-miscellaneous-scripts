
#ifndef _RC_LOCK_MOL2_API2_H_
#define _RC_LOCK_MOL2_API2_H_

#ifndef MOLECULEC_VERSION
#define MOLECULEC_VERSION 6001
#endif
#ifndef MOLECULE_API_VERSION_MIN
#define MOLECULE_API_VERSION_MIN 5000
#endif

#define MOLECULEC2_VERSION 6001
#define MOLECULE2_API_VERSION_MIN 5000

#include "molecule2_reader.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// ----forward declaration--------
struct IdentityType;
struct IdentityVTable;
struct IdentityVTable *GetIdentityVTable(void);
struct IdentityType make_Identity(mol2_cursor_t *cur);
uint32_t Identity_len_impl(struct IdentityType *);
uint8_t Identity_get_impl(struct IdentityType *, uint32_t, bool *);
struct SmtProofType;
struct SmtProofVTable;
struct SmtProofVTable *GetSmtProofVTable(void);
struct SmtProofType make_SmtProof(mol2_cursor_t *cur);
uint32_t SmtProof_len_impl(struct SmtProofType *);
uint8_t SmtProof_get_impl(struct SmtProofType *, uint32_t, bool *);
struct SmtProofEntryType;
struct SmtProofEntryVTable;
struct SmtProofEntryVTable *GetSmtProofEntryVTable(void);
struct SmtProofEntryType make_SmtProofEntry(mol2_cursor_t *cur);
uint8_t SmtProofEntry_get_mask_impl(struct SmtProofEntryType *);
mol2_cursor_t SmtProofEntry_get_proof_impl(struct SmtProofEntryType *);
struct SmtProofEntryVecType;
struct SmtProofEntryVecVTable;
struct SmtProofEntryVecVTable *GetSmtProofEntryVecVTable(void);
struct SmtProofEntryVecType make_SmtProofEntryVec(mol2_cursor_t *cur);
uint32_t SmtProofEntryVec_len_impl(struct SmtProofEntryVecType *);
struct SmtProofEntryType SmtProofEntryVec_get_impl(
    struct SmtProofEntryVecType *, uint32_t, bool *);
struct RcIdentityType;
struct RcIdentityVTable;
struct RcIdentityVTable *GetRcIdentityVTable(void);
struct RcIdentityType make_RcIdentity(mol2_cursor_t *cur);
mol2_cursor_t RcIdentity_get_identity_impl(struct RcIdentityType *);
struct SmtProofEntryVecType RcIdentity_get_proofs_impl(struct RcIdentityType *);
struct RcIdentityOptType;
struct RcIdentityOptVTable;
struct RcIdentityOptVTable *GetRcIdentityOptVTable(void);
struct RcIdentityOptType make_RcIdentityOpt(mol2_cursor_t *cur);
bool RcIdentityOpt_is_none_impl(struct RcIdentityOptType *);
bool RcIdentityOpt_is_some_impl(struct RcIdentityOptType *);
struct RcIdentityType RcIdentityOpt_unwrap_impl(struct RcIdentityOptType *);
struct RcLockWitnessLockType;
struct RcLockWitnessLockVTable;
struct RcLockWitnessLockVTable *GetRcLockWitnessLockVTable(void);
struct RcLockWitnessLockType make_RcLockWitnessLock(mol2_cursor_t *cur);
struct BytesOptType RcLockWitnessLock_get_signature_impl(
    struct RcLockWitnessLockType *);
struct RcIdentityOptType RcLockWitnessLock_get_rc_identity_impl(
    struct RcLockWitnessLockType *);

// ----definition-----------------
typedef struct IdentityVTable {
  uint32_t (*len)(struct IdentityType *);
  uint8_t (*get)(struct IdentityType *, uint32_t, bool *);
} IdentityVTable;
typedef struct IdentityType {
  mol2_cursor_t cur;
  IdentityVTable *t;
} IdentityType;

typedef struct SmtProofVTable {
  uint32_t (*len)(struct SmtProofType *);
  uint8_t (*get)(struct SmtProofType *, uint32_t, bool *);
} SmtProofVTable;
typedef struct SmtProofType {
  mol2_cursor_t cur;
  SmtProofVTable *t;
} SmtProofType;

typedef struct SmtProofEntryVTable {
  uint8_t (*mask)(struct SmtProofEntryType *);
  mol2_cursor_t (*proof)(struct SmtProofEntryType *);
} SmtProofEntryVTable;
typedef struct SmtProofEntryType {
  mol2_cursor_t cur;
  SmtProofEntryVTable *t;
} SmtProofEntryType;

typedef struct SmtProofEntryVecVTable {
  uint32_t (*len)(struct SmtProofEntryVecType *);
  struct SmtProofEntryType (*get)(struct SmtProofEntryVecType *, uint32_t,
                                  bool *);
} SmtProofEntryVecVTable;
typedef struct SmtProofEntryVecType {
  mol2_cursor_t cur;
  SmtProofEntryVecVTable *t;
} SmtProofEntryVecType;

typedef struct RcIdentityVTable {
  mol2_cursor_t (*identity)(struct RcIdentityType *);
  struct SmtProofEntryVecType (*proofs)(struct RcIdentityType *);
} RcIdentityVTable;
typedef struct RcIdentityType {
  mol2_cursor_t cur;
  RcIdentityVTable *t;
} RcIdentityType;

typedef struct RcIdentityOptVTable {
  bool (*is_none)(struct RcIdentityOptType *);
  bool (*is_some)(struct RcIdentityOptType *);
  struct RcIdentityType (*unwrap)(struct RcIdentityOptType *);
} RcIdentityOptVTable;
typedef struct RcIdentityOptType {
  mol2_cursor_t cur;
  RcIdentityOptVTable *t;
} RcIdentityOptType;

typedef struct RcLockWitnessLockVTable {
  struct BytesOptType (*signature)(struct RcLockWitnessLockType *);
  struct RcIdentityOptType (*rc_identity)(struct RcLockWitnessLockType *);
} RcLockWitnessLockVTable;
typedef struct RcLockWitnessLockType {
  mol2_cursor_t cur;
  RcLockWitnessLockVTable *t;
} RcLockWitnessLockType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
struct IdentityType make_Identity(mol2_cursor_t *cur) {
  IdentityType ret;
  ret.cur = *cur;
  ret.t = GetIdentityVTable();
  return ret;
}
struct IdentityVTable *GetIdentityVTable(void) {
  static IdentityVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = Identity_len_impl;
  s_vtable.get = Identity_get_impl;
  return &s_vtable;
}
uint32_t Identity_len_impl(IdentityType *this) { return 21; }
uint8_t Identity_get_impl(IdentityType *this, uint32_t index, bool *existing) {
  uint8_t ret = {0};
  mol2_cursor_res_t res = mol2_slice_by_offset2(&this->cur, 1 * index, 1);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret = convert_to_Uint8(&res.cur);
  return ret;
}
struct SmtProofType make_SmtProof(mol2_cursor_t *cur) {
  SmtProofType ret;
  ret.cur = *cur;
  ret.t = GetSmtProofVTable();
  return ret;
}
struct SmtProofVTable *GetSmtProofVTable(void) {
  static SmtProofVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = SmtProof_len_impl;
  s_vtable.get = SmtProof_get_impl;
  return &s_vtable;
}
uint32_t SmtProof_len_impl(SmtProofType *this) {
  return mol2_fixvec_length(&this->cur);
}
uint8_t SmtProof_get_impl(SmtProofType *this, uint32_t index, bool *existing) {
  uint8_t ret = {0};
  mol2_cursor_res_t res = mol2_fixvec_slice_by_index(&this->cur, 1, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret = convert_to_Uint8(&res.cur);
  return ret;
}
struct SmtProofEntryType make_SmtProofEntry(mol2_cursor_t *cur) {
  SmtProofEntryType ret;
  ret.cur = *cur;
  ret.t = GetSmtProofEntryVTable();
  return ret;
}
struct SmtProofEntryVTable *GetSmtProofEntryVTable(void) {
  static SmtProofEntryVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.mask = SmtProofEntry_get_mask_impl;
  s_vtable.proof = SmtProofEntry_get_proof_impl;
  return &s_vtable;
}
uint8_t SmtProofEntry_get_mask_impl(SmtProofEntryType *this) {
  uint8_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_Uint8(&ret2);
  return ret;
}
mol2_cursor_t SmtProofEntry_get_proof_impl(SmtProofEntryType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
struct SmtProofEntryVecType make_SmtProofEntryVec(mol2_cursor_t *cur) {
  SmtProofEntryVecType ret;
  ret.cur = *cur;
  ret.t = GetSmtProofEntryVecVTable();
  return ret;
}
struct SmtProofEntryVecVTable *GetSmtProofEntryVecVTable(void) {
  static SmtProofEntryVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = SmtProofEntryVec_len_impl;
  s_vtable.get = SmtProofEntryVec_get_impl;
  return &s_vtable;
}
uint32_t SmtProofEntryVec_len_impl(SmtProofEntryVecType *this) {
  return mol2_dynvec_length(&this->cur);
}
SmtProofEntryType SmtProofEntryVec_get_impl(SmtProofEntryVecType *this,
                                            uint32_t index, bool *existing) {
  SmtProofEntryType ret = {0};
  mol2_cursor_res_t res = mol2_dynvec_slice_by_index(&this->cur, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret.cur = res.cur;
  ret.t = GetSmtProofEntryVTable();
  return ret;
}
struct RcIdentityType make_RcIdentity(mol2_cursor_t *cur) {
  RcIdentityType ret;
  ret.cur = *cur;
  ret.t = GetRcIdentityVTable();
  return ret;
}
struct RcIdentityVTable *GetRcIdentityVTable(void) {
  static RcIdentityVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.identity = RcIdentity_get_identity_impl;
  s_vtable.proofs = RcIdentity_get_proofs_impl;
  return &s_vtable;
}
mol2_cursor_t RcIdentity_get_identity_impl(RcIdentityType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_array(&ret2);
  return ret;
}
SmtProofEntryVecType RcIdentity_get_proofs_impl(RcIdentityType *this) {
  SmtProofEntryVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetSmtProofEntryVecVTable();
  return ret;
}
struct RcIdentityOptType make_RcIdentityOpt(mol2_cursor_t *cur) {
  RcIdentityOptType ret;
  ret.cur = *cur;
  ret.t = GetRcIdentityOptVTable();
  return ret;
}
struct RcIdentityOptVTable *GetRcIdentityOptVTable(void) {
  static RcIdentityOptVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.is_none = RcIdentityOpt_is_none_impl;
  s_vtable.is_some = RcIdentityOpt_is_some_impl;
  s_vtable.unwrap = RcIdentityOpt_unwrap_impl;
  return &s_vtable;
}
bool RcIdentityOpt_is_none_impl(RcIdentityOptType *this) {
  return mol2_option_is_none(&this->cur);
}
bool RcIdentityOpt_is_some_impl(RcIdentityOptType *this) {
  return !mol2_option_is_none(&this->cur);
}
RcIdentityType RcIdentityOpt_unwrap_impl(RcIdentityOptType *this) {
  RcIdentityType ret;
  mol2_cursor_t cur = this->cur;
  ret.cur = cur;
  ret.t = GetRcIdentityVTable();
  return ret;
}
struct RcLockWitnessLockType make_RcLockWitnessLock(mol2_cursor_t *cur) {
  RcLockWitnessLockType ret;
  ret.cur = *cur;
  ret.t = GetRcLockWitnessLockVTable();
  return ret;
}
struct RcLockWitnessLockVTable *GetRcLockWitnessLockVTable(void) {
  static RcLockWitnessLockVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.signature = RcLockWitnessLock_get_signature_impl;
  s_vtable.rc_identity = RcLockWitnessLock_get_rc_identity_impl;
  return &s_vtable;
}
BytesOptType RcLockWitnessLock_get_signature_impl(RcLockWitnessLockType *this) {
  BytesOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetBytesOptVTable();
  return ret;
}
RcIdentityOptType RcLockWitnessLock_get_rc_identity_impl(
    RcLockWitnessLockType *this) {
  RcIdentityOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetRcIdentityOptVTable();
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _RC_LOCK_MOL2_API2_H_
