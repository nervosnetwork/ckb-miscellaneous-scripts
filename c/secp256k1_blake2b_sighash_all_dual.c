#include "blockchain.h"
#include "blake2b.h"
#include "ckb_syscalls.h"
#include "ckb_utils.h"
#include "secp256k1_helper.h"
#include "ckb_dlfcn.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define RECID_INDEX 64
#define SIGNATURE_SIZE 65
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define TEMP_SIZE 32768

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_VERIFICATION -12
#define ERROR_SECP_PARSE_PUBKEY -13
#define ERROR_SECP_PARSE_SIGNATURE -14
#define ERROR_SECP_SERIALIZE_PUBKEY -15
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_WITNESS_SIZE -22
#define ERROR_PUBKEY_BLAKE160_HASH -31

/* Extract lock from WitnessArgs */
int extract_witness_lock(uint8_t *witness, uint64_t len,
                         mol_seg_t *lock_bytes_seg) {
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t lock_seg = MolReader_WitnessArgs_get_lock(&witness_seg);

  if (MolReader_BytesOpt_is_none(&lock_seg)) {
    return ERROR_ENCODING;
  }
  *lock_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  return CKB_SUCCESS;
}

__attribute__((visibility("default"))) int
validate_secp256k1_blake2b_sighash_all(uint8_t *output_public_key_hash) {
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];
  uint64_t len = 0;

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  int ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  if (lock_bytes_seg.size != SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, witness_len);

  /* Digest same group witnesses */
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  /* Digest witnesses that not covered by inputs */
  i = ckb_calculate_inputs_len();
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  /* Load signature */
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  /* Check pubkey hash */
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, temp, pubkey_size);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  memcpy(output_public_key_hash, temp, BLAKE160_SIZE);

  return CKB_SUCCESS;
}

__attribute__((visibility("default"))) int
validate_simple() {
  int ret;
  uint64_t len = 0;

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  uint8_t public_key_hash[BLAKE160_SIZE];
  ret = validate_secp256k1_blake2b_sighash_all(public_key_hash);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (memcmp(args_bytes_seg.ptr, public_key_hash, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return 0;
}

#define OFFSETOF(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
#define PT_DYNAMIC 2

typedef struct {
  uint64_t type;
  uint64_t value;
} Elf64_Dynamic;

int main() {
  /*
   * A simply inlined program interpreter.
   *
   * Assuming ELF header lives at 0x0, also avoiding deferencing
   * NULL pointer.
   */
  uint64_t *phoff = (uint64_t *) OFFSETOF(Elf64_Ehdr, e_phoff);
  uint16_t *phnum = (uint16_t *) OFFSETOF(Elf64_Ehdr, e_phnum);
  Elf64_Phdr *program_headers = (Elf64_Phdr *) (*phoff);
;
  for (int i = 0; i < *phnum; i++) {
    Elf64_Phdr *program_header = &program_headers[i];
    if (program_header->p_type == PT_DYNAMIC) {
      Elf64_Dynamic *d = (Elf64_Dynamic *) program_header->p_vaddr;
      uint64_t rela_address = 0;
      uint64_t rela_count = 0;
      while (d->type != 0) {
        if (d->type == 0x7) {
          rela_address = d->value;
        } else if (d->type == 0x6ffffff9) {
          rela_count = d->value;
        }
        d++;
      }
      if (rela_address > 0 && rela_count > 0) {
        Elf64_Rela *relocations = (Elf64_Rela *) rela_address;
        for (int j = 0; j < rela_count; j++) {
          Elf64_Rela *relocation = &relocations[j];
          if (relocation->r_info != R_RISCV_RELATIVE) {
            return ERROR_INVALID_ELF;
          }
          *((uint64_t *)(relocation->r_offset)) = (uint64_t)(relocation->r_addend);
        }
      }
    }
  }
  return validate_simple();
}
