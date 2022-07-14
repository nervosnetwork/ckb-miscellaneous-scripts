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
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"

#include "secp256r1_helper.h"

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
#define RECID_INDEX 64
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

static const u8 test_signature[] = {
    0x68, 0x64, 0xf1, 0xf1, 0xfd, 0x70, 0xe8, 0x8d, 0x8e, 0x50, 0xed,
    0x17, 0xef, 0x8d, 0x78, 0x70, 0x15, 0xfa, 0x88, 0x3b, 0x0c, 0x34,
    0x2e, 0xfc, 0x36, 0xd6, 0x71, 0x48, 0xc2, 0x0f, 0x41, 0x8a, 0x38,
    0x91, 0x76, 0xba, 0x62, 0x24, 0xe2, 0x31, 0xb6, 0xa6, 0xa1, 0x3b,
    0x1c, 0xe5, 0x8a, 0x06, 0xca, 0xa7, 0x58, 0x58, 0xd1, 0x9f, 0x3e,
    0x68, 0xe8, 0x79, 0x0d, 0x67, 0x61, 0x7e, 0xc4, 0xe2};

static const u8 test_message[] = {
    0xf5, 0x5c, 0x2b, 0xdb, 0xac, 0x3e, 0x84, 0x03, 0x72, 0x28, 0xc3,
    0x0c, 0x4d, 0x04, 0x99, 0xf2, 0xfa, 0x95, 0x68, 0x26, 0x62, 0x7d,
    0x4c, 0xcf, 0xed, 0x6a, 0x01, 0xfd, 0xb6, 0x08, 0x68, 0xf1};

static const u8 test_priv_key[] = {
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
    0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
    0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};

static const u8 test_pub_key[] = {
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb,
    0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
    0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79,
    0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9,
    0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f,
    0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};

void my_pub_key_print(char *msg, const ec_pub_key *pub_key) {
  const u8 buf_size = 64;
  u8 temp_buf[buf_size];
  if (ec_pub_key_export_to_aff_buf(pub_key, temp_buf, buf_size)) {
    printf("export public key to buf failed");
  } else {
    buf_print(msg, temp_buf, buf_size);
  }
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
  secp256r1_context_t context;
  if (secp256r1_context_init(&context)) {
    return ERROR_SYSCALL;
  }
  ec_pub_key pub_key;
  if (secp256r1_pub_key_import_from_aff_buf(
          &context, &pub_key, args_bytes_seg.ptr, args_bytes_seg.size)) {
    printf("args_bytes_seg: ptr %p, size %d", args_bytes_seg.ptr,
           args_bytes_seg.size);
    buf_print("import public key failed", args_bytes_seg.ptr,
              args_bytes_seg.size);
    return ERROR_ENCODING;
  }

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
  if (lock_bytes_seg.size != SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  // We keep the signature in the temporary location, since later we will modify
  // the WitnessArgs object in place for message hashing.
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

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
  buf_print("blake2b tx_hash", tx_hash, BLAKE2B_BLOCK_SIZE);

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
  printf("updating blake2b len %d ", witness_len);
  buf_print("data", temp, witness_len);

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
    printf("updating blake2b len %d ", len);
    buf_print("data", temp, len);
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
    printf("updating blake2b len %d ", len);
    buf_print("data", temp, len);
    i += 1;
  }
  // Now the message preparation is completed.
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  // We are using bitcoin's [secp256k1
  // library](https://github.com/bitcoin-core/secp256k1) for signature
  // verification here. To the best of our knowledge, this is an unmatched
  // advantage of CKB: you can ship cryptographic algorithm within your smart
  // contract, you don't have to wait for the foundation to ship a new
  // cryptographic algorithm. You can just build and ship your own.

  ec_key_pair kp;
  if (local_memset(&kp, 0, sizeof(kp))) {
    return ERROR_UNREACHABLE;
  }
  secp256r1_get_key_pair_from_priv_key_buf(&context, &kp, test_priv_key,
                                           sizeof(test_priv_key));
  if (secp256r1_verify_signature(&context, test_signature,
                                 sizeof(test_signature), &kp.pub_key,
                                 test_message, sizeof(test_message))) {
    printf("TESTING fixed data FAILED\n");
  } else {
    printf("TESTING fixed data succeeded\n");
  };

  if (secp256r1_verify_signature(&context, lock_bytes, SIGNATURE_SIZE,
                                 &kp.pub_key, message, BLAKE2B_BLOCK_SIZE)) {
    printf("TESTING with public key from private key FAILED\n");
  } else {
    printf("TESTING with public key from private key succeeded\n");
  };

  ec_pub_key pub_key2;
  if (local_memset(&pub_key2, 0, sizeof(pub_key2))) {
    return ERROR_UNREACHABLE;
  }
  if (secp256r1_pub_key_import_from_aff_buf(&context, &pub_key2, test_pub_key,
                                            sizeof(test_pub_key))) {
    buf_print("import public key failed", test_pub_key, sizeof(test_pub_key));
    return ERROR_ENCODING;
  }
  if (secp256r1_verify_signature(&context, test_signature,
                                 sizeof(test_signature), &pub_key2,
                                 test_message, sizeof(test_message))) {
    printf("TESTING with fixed public_key imported from buffer FAILED\n");
  } else {
    printf("TESTING with fixed public_key imported from buffer succeeded\n");
  };

  ec_pub_key pub_key3;
  if (local_memset(&pub_key3, 0, sizeof(pub_key3))) {
    return ERROR_UNREACHABLE;
  }
  const u8 buf_size = 64;
  u8 temp_buf[buf_size];
  if (local_memset(&temp_buf, 0, sizeof(temp_buf))) {
    return ERROR_UNREACHABLE;
  }
  if (ec_pub_key_export_to_aff_buf(&kp.pub_key, temp_buf, buf_size)) {
    return ERROR_ENCODING;
  }
  if (secp256r1_pub_key_import_from_aff_buf(&context, &pub_key3, temp_buf,
                                            buf_size)) {
    return ERROR_ENCODING;
  }
  if (secp256r1_verify_signature(&context, test_signature,
                                 sizeof(test_signature), &pub_key2,
                                 test_message, sizeof(test_message))) {
    printf("TESTING with public_key imported from the buffer exported from key "
           "pair FAILED\n");
  } else {
    printf("TESTING with public_key imported from the buffer exported from key "
           "pair succeeded\n");
  };

  // pub_key from arguments
  if (secp256r1_verify_signature(&context, test_signature,
                                 sizeof(test_signature), &pub_key, test_message,
                                 sizeof(test_message))) {
    printf("TESTING with public_key from arguments FAILED\n");
  } else {
    printf("TESTING with public_key from arguments succeeded\n");
  };

  my_pub_key_print("kp.pub_key (public key imported from private key)",
                   &kp.pub_key);
  my_pub_key_print("pub_key (public key passed from rust)", &pub_key);
  my_pub_key_print("pub_key2 (public key imported from fixed buffer)",
                   &pub_key2);
  my_pub_key_print(
      "pub_key3 (public key imported from the buffer exported from key pair)",
      &pub_key3);

  if (secp256r1_verify_signature(&context, lock_bytes, SIGNATURE_SIZE, &pub_key,
                                 message, BLAKE2B_BLOCK_SIZE)) {
    return ERROR_SECP_VERIFICATION;
  };

  return 0;
}
