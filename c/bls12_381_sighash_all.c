// uncomment to enable printf in CKB-VM
// #define CKB_C_STDLIB_PRINTF

// it's used by blockchain-api2.h, the behavior when panic
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);

// clang-format off
#include <stdio.h>
#include <blake2b.h>
#include "blockchain-api2.h"
#include "blockchain.h"
#include "ckb_consts.h"
#include "ckb_syscalls.h"
#include "rc_lock_mol2.h"
#include "blst.h"

// clang-format on

#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#define CHECK(_code)    \
  do {                  \
    int code = (_code); \
    if (code != 0) {    \
      err = code;       \
      ASSERT(0);        \
      goto exit;        \
    }                   \
  } while (0)

#define SCRIPT_SIZE 32768
#define MAX_LOCK_SCRIPT_HASH_COUNT 2048

#define CKB_IDENTITY_LEN 21
#define RECID_INDEX 64
#define ONE_BATCH_SIZE 32768
#define BLST_PUBKEY_SIZE 48
#define MAX_WITNESS_SIZE 32768
#define BLST_SIGNAUTRE_SIZE (48 + 96)
#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20

const static uint8_t g_dst_label[] =
    "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const static size_t g_dst_label_len = 43;

enum CkbIdentityErrorCode {
  ERROR_IDENTITY_ARGUMENTS_LEN = -1,
  ERROR_IDENTITY_ENCODING = -2,
  ERROR_IDENTITY_SYSCALL = -3,

  // compatible with secp256k1 pubkey hash verification
  ERROR_IDENTITY_SECP_RECOVER_PUBKEY = -11,
  ERROR_IDENTITY_SECP_PARSE_SIGNATURE = -14,
  ERROR_IDENTITY_SECP_SERIALIZE_PUBKEY = -15,
  ERROR_IDENTITY_PUBKEY_BLAKE160_HASH = -31,
  // new error code
  ERROR_IDENTITY_LOCK_SCRIPT_HASH_NOT_FOUND = 70,
  ERROR_INVALID_MOL_FORMAT,
  ERROR_BLST_VERIFY_FAILED,
};

typedef struct CkbIdentityType {
  uint8_t flags;
  // blake160 (20 bytes) hash of lock script or pubkey
  uint8_t blake160[20];
} CkbIdentityType;

enum IdentityFlagsType {
  IdentityFlagsPubkeyHash = 0,
  IdentityFlagsOwnerLock = 1,
  IdentityFlagsBls12381 = 15,
};

static BLST_ERROR blst_verify(const uint8_t *sig, const uint8_t *pk,
                              const uint8_t *msg, size_t msg_len) {
  BLST_ERROR err;
  blst_p1_affine pk_p1_affine;
  blst_p1_uncompress(&pk_p1_affine, pk);
  blst_p2_affine sig_p2_affine;
  blst_p2_uncompress(&sig_p2_affine, sig);

#if 1
  // using one-shot
  printf("using one-shot\n");
  err =
      blst_core_verify_pk_in_g1(&pk_p1_affine, &sig_p2_affine, true, msg,
                                msg_len, g_dst_label, g_dst_label_len, NULL, 0);
  CHECK(err);
#else
  // using pairing interface

  // pubkey must be checked
  // signature will be checked internally later.
  printf("using pairing interface\n");
  uint8_t ctx_buff[blst_pairing_sizeof()];

  bool in_g1 = blst_p1_affine_in_g1(&pk_p1_affine);
  CHECK2(in_g1, -1);

  blst_pairing *ctx = (blst_pairing *)ctx_buff;
  blst_pairing_init(ctx, true, g_dst_label, g_dst_label_len);
  err = blst_pairing_aggregate_pk_in_g1(ctx, &pk_p1_affine, &sig_p2_affine, msg,
                                        msg_len, NULL, 0);
  CHECK(err);
  blst_pairing_commit(ctx);

  bool b = blst_pairing_finalverify(ctx, NULL);
  CHECK2(b, -1);
#endif

exit:
  return err;
}

static int extract_witness_lock(uint8_t *witness, uint64_t len,
                                mol_seg_t *lock_bytes_seg) {
  if (len < 20) {
    return ERROR_IDENTITY_ENCODING;
  }
  uint32_t lock_length = *((uint32_t *)(&witness[16]));
  if (len < 20 + lock_length) {
    return ERROR_IDENTITY_ENCODING;
  } else {
    lock_bytes_seg->ptr = &witness[20];
    lock_bytes_seg->size = lock_length;
  }
  return CKB_SUCCESS;
}

int load_and_hash_witness(blake2b_state *ctx, size_t start, size_t index,
                          size_t source, bool hash_length) {
  uint8_t temp[ONE_BATCH_SIZE];
  uint64_t len = ONE_BATCH_SIZE;
  int ret = ckb_load_witness(temp, &len, start, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (hash_length) {
    blake2b_update(ctx, (char *)&len, sizeof(uint64_t));
  }
  uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
  blake2b_update(ctx, temp, offset);
  while (offset < len) {
    uint64_t current_len = ONE_BATCH_SIZE;
    ret = ckb_load_witness(temp, &current_len, start + offset, index, source);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    uint64_t current_read =
        (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
    blake2b_update(ctx, temp, current_read);
    offset += current_read;
  }
  return CKB_SUCCESS;
}

int verify_bls12_381_blake160_sighash_all(uint8_t *pubkey_hash,
                                          uint8_t *signature_bytes) {
  int ret;
  uint64_t len = 0;
  unsigned char temp[MAX_WITNESS_SIZE];
  uint64_t read_len = MAX_WITNESS_SIZE;
  uint64_t witness_len = MAX_WITNESS_SIZE;

  /* Load witness of first input */
  ret = ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_IDENTITY_SYSCALL;
  }
  witness_len = read_len;
  if (read_len > MAX_WITNESS_SIZE) {
    read_len = MAX_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, read_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_IDENTITY_ENCODING;
  }
  if (lock_bytes_seg.size < BLST_SIGNAUTRE_SIZE) {
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  }
  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_IDENTITY_SYSCALL;
  }

  /* Prepare sign message */
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness
   * lock_bytes_seg.ptr actually points to the memory in temp buffer
   * */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, read_len);

  // remaining of first witness
  if (read_len < witness_len) {
    ret = load_and_hash_witness(&blake2b_ctx, read_len, 0,
                                CKB_SOURCE_GROUP_INPUT, false);
    if (ret != CKB_SUCCESS) {
      return ERROR_IDENTITY_SYSCALL;
    }
  }

  // Digest same group witnesses
  size_t i = 1;
  while (1) {
    ret =
        load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_GROUP_INPUT, true);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_IDENTITY_SYSCALL;
    }
    i += 1;
  }

  // Digest witnesses that not covered by inputs
  i = (size_t)ckb_calculate_inputs_len();
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_INPUT, true);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_IDENTITY_SYSCALL;
    }
    i += 1;
  }

  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  const uint8_t *pubkey = signature_bytes;
  const uint8_t *sig = pubkey + BLST_PUBKEY_SIZE;

  BLST_ERROR err = blst_verify(sig, pubkey, message, BLAKE2B_BLOCK_SIZE);
  if (err != 0) {
    return ERROR_BLST_VERIFY_FAILED;
  }

  unsigned char temp2[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx2;
  blake2b_init(&blake2b_ctx2, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx2, pubkey, BLST_PUBKEY_SIZE);
  blake2b_final(&blake2b_ctx2, temp2, BLAKE2B_BLOCK_SIZE);

  if (memcmp(pubkey_hash, temp2, BLAKE160_SIZE) != 0) {
    return ERROR_IDENTITY_PUBKEY_BLAKE160_HASH;
  }

  return 0;
}

int ckb_verify_bls12_381_identity(CkbIdentityType *id, uint8_t *signature) {
  if (id->flags == IdentityFlagsBls12381) {
    return verify_bls12_381_blake160_sighash_all(id->blake160, signature);
  } else {
    return CKB_INVALID_DATA;
  }
}

enum RcLockErrorCode {
  // rc lock error code is starting from 80
  ERROR_UNKNOWN_FLAGS = 80,
  ERROR_PROOF_LENGTH_MISMATCHED,
  ERROR_NO_RCRULE,
  ERROR_NO_WHITE_LIST,
};

typedef struct ArgsType {
  CkbIdentityType id;
  uint8_t rc_root[32];
} ArgsType;

// make compiler happy
int make_cursor_from_witness(WitnessArgsType *witness, bool *_input) {
  return -1;
}

int parse_args(ArgsType *args, bool has_rc_identity) {
  int err = 0;
  uint8_t script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  err = ckb_checked_load_script(script, &len, 0);
  CHECK(err);

  mol_seg_t script_seg;
  script_seg.ptr = script;
  script_seg.size = (mol_num_t)len;

  mol_errno mol_err = MolReader_Script_verify(&script_seg, false);
  CHECK2(mol_err == MOL_OK, ERROR_IDENTITY_ENCODING);

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  CHECK2(args_bytes_seg.size >= 1, ERROR_IDENTITY_ENCODING);
  uint8_t flags = args_bytes_seg.ptr[0];
  CHECK2(flags == IdentityFlagsPubkeyHash || flags == IdentityFlagsOwnerLock ||
             flags == IdentityFlagsBls12381,
         ERROR_UNKNOWN_FLAGS);
  args->id.flags = flags;

  CHECK2(args_bytes_seg.size >= (1 + BLAKE160_SIZE), ERROR_INVALID_MOL_FORMAT);
  memcpy(args->id.blake160, args_bytes_seg.ptr + 1, BLAKE160_SIZE);

  if (has_rc_identity) {
    CHECK2(args_bytes_seg.size >= (1 + BLAKE160_SIZE + BLAKE2B_BLOCK_SIZE),
           ERROR_INVALID_MOL_FORMAT);
    memcpy(args->rc_root, args_bytes_seg.ptr + 1 + BLAKE160_SIZE,
           sizeof(args->rc_root));
  }

exit:
  return err;
}

static uint32_t read_from_witness(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                                  uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_witness(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

uint8_t g_witness_data_source[DEFAULT_DATA_SOURCE_LENGTH];
int make_witness(WitnessArgsType *witness) {
  int err = 0;
  uint64_t witness_len = 0;
  size_t source = CKB_SOURCE_GROUP_INPUT;
  err = ckb_load_witness(NULL, &witness_len, 0, 0, source);
  // when witness is missing, empty or not accessible, make it zero length.
  // don't fail, because owner lock without rc doesn't require witness.
  // when it's zero length, any further actions on witness will fail.
  if (err != 0) {
    witness_len = 0;
  }

  mol2_cursor_t cur;

  cur.offset = 0;
  cur.size = (mol_num_t)witness_len;

  mol2_data_source_t *ptr = (mol2_data_source_t *)g_witness_data_source;

  ptr->read = read_from_witness;
  ptr->total_size = (uint32_t)witness_len;
  // pass index and source as args
  ptr->args[0] = 0;
  ptr->args[1] = source;

  ptr->cache_size = 0;
  ptr->start_point = 0;
  ptr->max_cache_size = MAX_CACHE_SIZE;
  cur.data_source = ptr;

  *witness = make_WitnessArgs(&cur);

  return 0;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main() {
#endif
  int err = 0;
  // if has_rc_identity is true, it's one of the following:
  // - Unlock via administrator’s lock script hash
  // - Unlock via administrator’s public key hash
  bool has_rc_identity = false;
  CkbIdentityType identity = {0};
  RcIdentityType rc_identity = {0};
  bool witness_lock_existing = false;
  bool witness_existing = false;

  WitnessArgsType witness;
  err = make_witness(&witness);
  CHECK(err);
  witness_existing = witness.cur.size > 0;

  BytesOptType lock = {0};
  mol2_cursor_t lock_bytes = {0};
  RcLockWitnessLockType witness_lock = {0};

  // witness or witness lock can be empty if owner lock without rc is used
  if (witness_existing) {
    lock = witness.t->lock(&witness);
    if (!lock.t->is_none(&lock)) {
      witness_lock_existing = true;
      lock_bytes = lock.t->unwrap(&lock);
      // convert Bytes to RcLockWitnessLock
      witness_lock = make_RcLockWitnessLock(&lock_bytes);
      RcIdentityOptType rc_identity_opt =
          witness_lock.t->rc_identity(&witness_lock);
      has_rc_identity = rc_identity_opt.t->is_some(&rc_identity_opt);
      if (has_rc_identity) {
        rc_identity = rc_identity_opt.t->unwrap(&rc_identity_opt);
        mol2_cursor_t id_cur = rc_identity.t->identity(&rc_identity);
        uint8_t buff[CKB_IDENTITY_LEN] = {0};
        uint32_t read_len = mol2_read_at(&id_cur, buff, sizeof(buff));
        CHECK2(read_len == CKB_IDENTITY_LEN, ERROR_INVALID_MOL_FORMAT);
        identity.flags = buff[0];
        memcpy(identity.blake160, buff + 1, CKB_IDENTITY_LEN - 1);
      }
    } else {
      witness_lock_existing = false;
    }
  } else {
    witness_lock_existing = false;
  }

  ArgsType args = {0};
  err = parse_args(&args, has_rc_identity);
  CHECK(err);
  // When rc_identity is missing, the identity included in lock script args will
  // then be used in further validation.
  if (!has_rc_identity) {
    identity = args.id;
  }

  uint8_t signature_bytes[BLST_SIGNAUTRE_SIZE] = {0};
  if (identity.flags == IdentityFlagsBls12381) {
    CHECK2(witness_lock_existing, ERROR_INVALID_MOL_FORMAT);

    BytesOptType signature_opt = witness_lock.t->signature(&witness_lock);
    mol2_cursor_t signature_cursor = signature_opt.t->unwrap(&signature_opt);

    uint32_t read_len =
        mol2_read_at(&signature_cursor, signature_bytes, BLST_SIGNAUTRE_SIZE);
    CHECK2(read_len == BLST_SIGNAUTRE_SIZE, ERROR_INVALID_MOL_FORMAT);
  } else {
    return ERROR_IDENTITY_ENCODING;
  }

  err = ckb_verify_bls12_381_identity(&identity, signature_bytes);
  CHECK(err);

exit:
  return err;
}
