
#include <stddef.h>
#include <stdint.h>

#include "ckb_dlfcn_decl_only.h"
#define CKB_C_STDLIB_CKB_DLFCN_H_ 1

#include "ckb_syscalls_decl_only.h"
#define CKB_C_STDLIB_CKB_SYSCALLS_H_ 1

#include <simulator/blake2b_decl_only.h>
#define BLAKE2_H 1
#define BLAKE2_IMPL_H 1
#define BLAKE2_REF_C 1

#include <simulator/molecule_decl_only.h>
#define BLOCKCHAIN_H 1
#define MOLECULE_BUILDER_H 1
#define MOLECULE_READER_H 1

#define validate_signature validate_signature_secp256k1
#define load_and_hash_witness load_and_hash_witness_secp256k1
#define extract_witness_lock extract_witness_lock_secp256k1
#define main not_main
#include "rsa_secp256k1.h"
#include "secp256k1_blake2b_sighash_all_dual.c"
