/*
 * A simple composable OR lock script. It runs each lock script in
 * sequence, as long as any lock script passes, it returns a success
 * state, otherwise it returns a failure.
 */
#include "ckb_dlfcn.h"
#include "ckb_syscalls.h"
#include "or.h"

#define CODE_SIZE (256 * 1024)
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768

#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_DYNAMIC_LOADING -103
#define ERROR_TOO_LONG -104
#define ERROR_ONE_FAILURE -106

int main() {
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t or_scripts_seg = MolReader_Bytes_raw_bytes(&args_seg);

  unsigned char witness[MAX_WITNESS_SIZE];
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_TOO_LONG;
  }
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;
  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t lock_opt_seg = MolReader_WitnessArgs_get_lock(&witness_seg);
  if (MolReader_BytesOpt_is_none(&lock_opt_seg)) {
    return ERROR_ENCODING;
  }
  mol_seg_t or_witnesses_seg = MolReader_Bytes_raw_bytes(&lock_opt_seg);

  if ((MolReader_OrScripts_verify(&or_scripts_seg, false) != MOL_OK) ||
      (MolReader_OrWitnesses_verify(&or_witnesses_seg, false) != MOL_OK) ||
      (MolReader_OrScripts_length(&or_scripts_seg) !=
       MolReader_OrScripts_length(&or_witnesses_seg))) {
    return ERROR_ENCODING;
  }
  uint8_t code_buffer[CODE_SIZE] __attribute__((aligned(RISCV_PGSIZE)));
  size_t used_size = 0;
  for (size_t i = 0; i < MolReader_OrScripts_length(&or_scripts_seg); i++) {
    mol_seg_res_t script_res = MolReader_OrScripts_get(&or_scripts_seg, i);
    mol_seg_res_t witness_res = MolReader_OrWitnesses_get(&or_witnesses_seg, i);
    if (script_res.errno != MOL_OK || witness_res.errno != MOL_OK) {
      return ERROR_ENCODING;
    }
    mol_seg_t script = script_res.seg;
    mol_seg_t witness = witness_res.seg;

    /* TODO: type hash type support */
    mol_seg_t hash_type = MolReader_Script_get_hash_type(&script);
    if (hash_type.ptr[0] != 0) {
      return ERROR_ENCODING;
    }
    mol_seg_t code_hash = MolReader_Script_get_code_hash(&script);
    if (code_hash.size != 32) {
      return ERROR_ENCODING;
    }
    void *handle = NULL;
    uint64_t consumed_size = 0;
    int ret = ckb_dlopen(code_hash.ptr, &code_buffer[used_size],
                         CODE_SIZE - used_size, &handle, &consumed_size);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    int (*verify)(const mol_seg_t *, const mol_seg_t *);
    *(void **)(&verify) = ckb_dlsym(handle, "verify");
    if (verify == NULL) {
      return ERROR_DYNAMIC_LOADING;
    }
    ret = verify(&script, &witness);
    if (ret != CKB_SUCCESS) {
      return ERROR_ONE_FAILURE;
    }
  }
  return CKB_SUCCESS;
}
