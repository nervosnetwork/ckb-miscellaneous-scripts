// # secp256k1-blake160-sighash-all
//
// This is a lock script code using the same secp256k1 signature verification
// algorithm as used in bitcoin. When executed, it performs the blake2b hash
// (with "ckb-default-hash" used as the personalization value) on the following
// concatenated components:
//
// * The current transaction hash;
// * Take the witness of the same index as the first input using current lock
// script, treat it as a
// [WitnessArgs](https://github.com/nervosnetwork/ckb/blob/1df5f2c1cbf07e04622fb8faa5b152c1af7ae341/util/types/schemas/blockchain.mol#L106)
// object using molecule serialization format, then fill in a 65-byte long value
// with all zeros in the lock field, the modified object is then serialized and
// used as the value to hash. Notice the length of the modified witness object
// is hashed first as a 64-bit unsigned little endian integer;
// * All the witnesses of the same indices as the remaining input cells with the
// same lock script as the current lock script to run. Notice the length of each
// witness is hashed before the corresponding witness as a 64-bit unsigned
// little endian integer;
// * All the witnesses which have index value exceeding the number of input
// cells. For example, if a transaction has 3 inputs, all witnesses with index
// equal to or larger than 3 will be hashed. Notice the length of each witness
// is hashed before the corresponding witness as a 64-bit unsigned little endian
// integer;
//
// The blake2b hash result is then used as a message to verify the recoverable
// signature provided in the lock field of the modified witness object mentioned
// above. From the recoverable signature, we can derive the public key, we then
// run another blake2b hash (with "ckb-default-hash" used as personalization),
// take the first 160 bit of the hashed result(hence the blake160 name), and
// compare those 160-bit values with what is stored in script args part of
// current running script. If they do match, the signature verification is
// succeeded.
//
// Note that we distinguish between lock script and lock script code here: when
// we say lock script code, we mean only the RISC-V binary compiled from the
// current C source file; when we say lock script, however, we mean the whole
// lock script including script args part. A consequence here, is that one
// transaction in CKB might contain input cells using the same lock script code
// here, but with different script args(hence different lock script), in those
// cases, this underlying lock script code will be executed multiple times when
// validating a single transaction, each time with a different lock script.

// First we will need to include a few headers here, for legacy reasons, this
// repository ships with those headers. We are now maintaining a new
// [repository](https://github.com/nervosnetwork/ckb-c-stdlib) with most of
// those headers included. If you are building a new script, we do recommend you
// to take a look at what's in the new repository, and use the code there
// directly.

#define CKB_C_STDLIB_PRINTF

#include <stdio.h>

#include "blake2b.h"
#include "blockchain.h"
#include "ckb_syscalls.h"
#include "common.h"

#include "lib_ecc_types.h"
#include "libec.h"
#include "libsig.h"

// Common definitions here, one important limitation, is that this lock script
// only works with scripts and witnesses that are no larger than 32KB. We
// believe this should be enough for most cases.
//
// Here we are also employing a common convention: we append the recovery ID to
// the end of the 64-byte compact recoverable signature.
#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 64
#define TEMP_SIZE 32768
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 64
#define LOCK_SIZE (PUBKEY_SIZE + SIGNATURE_SIZE)

// Compile-time guard against buffer abuse
#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

// To use this script, some conventions are required:
//
// The script args part should contain the blake160 hash of a public key, which
// is the first 20 bytes of the blake2b hash(with "ckb-default-hash" as
// personalization) of the used public key. This is used to shield the real
// public key till the first spend.
//
// The first witness, or the first witness of the same index as the first input
// cell using current lock script, should be a
// [WitnessArgs](https://github.com/nervosnetwork/ckb/blob/1df5f2c1cbf07e04622fb8faa5b152c1af7ae341/util/types/schemas/blockchain.mol#L106)
// object in molecule serialization format. The lock field of said WitnessArgs
// object should contain a 65-byte recoverable signature to prove ownership.

static const char *ec_name = "SECP256R1";

static const char *ec_sig_name = "ECDSA";

static const char *hash_algorithm = "SHA256";

const u32 projective_buffer_size = 96;
const u32 affine_buffer_size = 64;

/* Print the buffer of a given size */
void my_buf_print(const char *msg, const u8 *buf, u16 buflen) {
  u32 i;

  if (buf == NULL) {
    return;
  }

  if (msg != NULL) {
    printf("%s: ", msg);
  }

  for (i = 0; i < (u32)buflen; i++) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}

int get_random(unsigned char *buf, u16 len) {
  for (int i = 0; i < len; i++) {
    buf[i] = 0;
  }
  return 0;
}

static int string_to_params(const char *ec_name, const char *ec_sig_name,
                            ec_sig_alg_type *sig_type,
                            const ec_str_params **ec_str_p,
                            const char *hash_name, hash_alg_type *hash_type) {
  const ec_str_params *curve_params;
  const ec_sig_mapping *sm;
  const hash_mapping *hm;
  u32 curve_name_len;

  if (sig_type != NULL) {
    /* Get sig type from signature alg name */
    sm = get_sig_by_name(ec_sig_name);
    if (!sm) {
      printf("Error: signature type %s is unknown!\n", ec_sig_name);
      goto err;
    }
    *sig_type = sm->type;
  }

  if (ec_str_p != NULL) {
    /* Get curve params from curve name */
    curve_name_len = local_strlen((const char *)ec_name) + 1;
    if (curve_name_len > 255) {
      /* Sanity check */
      goto err;
    }
    curve_params =
        ec_get_curve_params_by_name((const u8 *)ec_name, (u8)curve_name_len);
    if (!curve_params) {
      printf("Error: EC curve %s is unknown!\n", ec_name);
      goto err;
    }
    *ec_str_p = curve_params;
  }

  if (hash_type != NULL) {
    /* Get hash type from hash alg name */
    hm = get_hash_by_name(hash_name);
    if (!hm) {
      printf("Error: hash function %s is unknown!\n", hash_name);
      goto err;
    }
    *hash_type = hm->type;
  }

  return 0;

err:
  return -1;
}

void convert_aff_buf_to_prj_buf(const u8 *aff_buf, u32 aff_buf_len, u8 *prj_buf,
                                u32 prj_buf_len) {
  static const u8 z_buf[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  MUST_HAVE(aff_buf_len == affine_buffer_size);
  MUST_HAVE(prj_buf_len == projective_buffer_size);
  memcpy(prj_buf, aff_buf, aff_buf_len);
  memcpy(prj_buf + aff_buf_len, z_buf, sizeof(z_buf));
}

int verify_signature(const u8 *sig, u8 siglen, const u8 *pk, u32 pklen,
                     const u8 *m, u32 mlen) {
  const ec_str_params *ec_str_p;
  ec_sig_alg_type sig_type;
  hash_alg_type hash_type;
  ec_pub_key pub_key;
  ec_params params;
  int ret;

  // ec_pub_key_import_from_buf requires a buffer which represents the
  // projective point of the public key, the parameter passed to here is an
  // affine buffer. We convert the affine buffer to projective buffer here.
  u8 pj_pk_buf[projective_buffer_size];
  convert_aff_buf_to_prj_buf(pk, pklen, pj_pk_buf, sizeof(pj_pk_buf));

  MUST_HAVE(ec_name != NULL);

  /************************************/
  /* Get parameters from pretty names */
  ret = string_to_params(ec_name, ec_sig_name, &sig_type, &ec_str_p,
                         hash_algorithm, &hash_type);
  if (ret) {
    printf("Error: error when getting ec parameter\n");
    goto err;
  }
  /* Import the parameters */
  import_params(&params, ec_str_p);

  ret = ec_pub_key_import_from_buf(&pub_key, &params, pj_pk_buf,
                                   sizeof(pj_pk_buf), sig_type);
  if (ret) {
    printf("Error: error when importing public key from\n");
    goto err;
  }

  ret = ec_verify(sig, siglen, &pub_key, m, mlen, sig_type, hash_type);

  if (ret) {
    printf("Error: error while verifying signature\n");
    goto err;
  }

  return 0;

err:
  printf("Error while verifying signature %d\n", ret);
  return ret;
}

int main() {
  int ret;
  uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[LOCK_SIZE];

  // First let's load and extract script args part, which is also the blake160
  // hash of public key from current running script.
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

  // Load the first witness, or the witness of the same index as the first
  // input using current script.
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // We will treat the first witness as WitnessArgs object, and extract the lock
  // field from the object.
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  // The lock field must be 65 byte long to represent a (possibly) valid
  // signature.
  if (lock_bytes_seg.size != LOCK_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  // We keep the signature in the temporary location, since later we will modify
  // the WitnessArgs object in place for message hashing.
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

  blake2b_state blake2b_ctx_pk;
  unsigned char hash_result[BLAKE2B_BLOCK_SIZE];
  blake2b_init(&blake2b_ctx_pk, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx_pk, lock_bytes, PUBKEY_SIZE);
  blake2b_final(&blake2b_ctx_pk, hash_result, BLAKE2B_BLOCK_SIZE);

  if (memcmp(args_bytes_seg.ptr, hash_result, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  // Load the current transaction hash.
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  // Here we start to prepare the message used in signature verification. First,
  // let's hash the just loaded transaction hash.
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  // We've already saved the signature above to a different location. We can
  // then modify the witness object in place to save both memory usage and
  // runtime cycles. The message requires us to use all zeros in the place where
  // a signature should be presented.
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  // Before hashing each witness, we need to hash the witness length first as a
  // 64-bit unsigned little endian integer.
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  // Now let's hash the first modified witness.
  blake2b_update(&blake2b_ctx, temp, witness_len);

  // Let's loop and hash all witnesses with the same indices as the remaining
  // input cells using current running lock script.
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    // Using *CKB_SOURCE_GROUP_INPUT* as the source value provides us with a
    // quick way to loop through all input cells using current running lock
    // script. We don't have to loop and check each individual cell by
    // ourselves.
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
    // Before hashing each witness, we need to hash the witness length first as
    // a 64-bit unsigned little endian integer.
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  // For safety consideration, this lock script will also hash and guard all
  // witnesses that have index values equal to or larger than the number of
  // input cells. It assumes all witnesses that do have an input cell with the
  // same index, will be guarded by the lock script of the input cell.
  //
  // For convenience reason, we provide a utility function here to calculate the
  // number of input cells in a transaction.
  i = calculate_inputs_len();
  while (1) {
    len = MAX_WITNESS_SIZE;
    // Here we are guarding input cells with any arbitrary lock script, hence we
    // are using the plain *CKB_SOURCE_INPUT* source to loop all witnesses.
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
    // Before hashing each witness, we need to hash the witness length first as
    // a 64-bit unsigned little endian integer.
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  // Now the message preparation is completed.
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  if (verify_signature(lock_bytes + PUBKEY_SIZE, SIGNATURE_SIZE, lock_bytes,
                       PUBKEY_SIZE, message, BLAKE2B_BLOCK_SIZE)) {
    return ERROR_SECP_VERIFICATION;
  };

  return 0;
}
