#include "ckb_smt.h"

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
#define ERROR_INVALID_PREFILLED_DATA_SIZE -41
#define ERROR_INVALID_SIGNATURE_SIZE -42
#define ERROR_INVALID_MESSAGE_SIZE -43
#define ERROR_INVALID_OUTPUT_SIZE -44

__attribute__((visibility("default"))) int ckb_smt_verify(
    const uint8_t *root, const uint32_t smt_pair_len,  const uint8_t *keys, const uint8_t *values,  const uint8_t *proof, uint32_t proof_length
    )
{
    smt_pair_t smt_pair [1024];
    smt_state_t smt_state;
    smt_state_init(&smt_state,(smt_pair_t *)&smt_pair,1024);
    for (int i = 0;i < smt_pair_len;i++){
        smt_state_insert(&smt_state,&keys[i  * SMT_KEY_BYTES],&values[i * SMT_VALUE_BYTES]);
    }
    smt_state_normalize(&smt_state);
    int ret = smt_verify(root,&smt_state,proof,proof_length);
    return ret;
}