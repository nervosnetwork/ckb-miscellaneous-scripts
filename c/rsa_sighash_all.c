// # rsa_sighash_all
// same as secp256k1_blake2b_sighash_all_dual but with RSA (mbedtls)

#include "ckb_consts.h"
#if defined(USE_SIM)
#include "ckb_syscall_sim.h"
#else
#include "ckb_syscalls.h"
#endif

#include "blake2b.h"
#include "blockchain.h"
#include "ckb_dlfcn.h"
#include "ckb_utils.h"
#include "secp256k1_helper.h"

#include "mbedtls/config.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"

#include "rsa_sighash_all.h"

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_RSA_INVALID_PARAM -51

#if defined(USE_SIM)
#define mbedtls_printf printf
#else
#define mbedtls_printf(x, ...)  (void)0
#endif

// Extract lock from WitnessArgs
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

/**
 * Note: there is no prefilled data for RSA, it's only be used in secp256k1.
 * Always succeed.
 * @param data
 * @param len
 * @return
 */
__attribute__((visibility("default"))) int load_prefilled_data(void *data,
                                                               size_t *len) {
    *len = 0;
    return CKB_SUCCESS;
}

__attribute__((visibility("default"))) int validate_signature(
        void *prefilled_data, const uint8_t *signature_buffer,
        size_t signature_size, const uint8_t *message_buffer, size_t message_size,
        uint8_t *output, size_t *output_len) {
    int ret;
    int exit_code = EXIT_FAILURE;
    mbedtls_rsa_context rsa;
    unsigned char hash[32];
    signature_t* input_info = (signature_t*)signature_buffer;

    // TODO: check buff size
    // TODO: check parameters

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    // double check: can use like this?
    mbedtls_mpi_read_binary(&rsa.E, (const unsigned char*)&input_info->E, 4);
    mbedtls_mpi_read_binary(&rsa.N, (const unsigned char*)&input_info->N, input_info->key_size/8);

    rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

    mbedtls_printf("\nVerifying the RSA/SHA-256 signature");
    ret = md_string(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), message_buffer, message_size, hash);
    if (ret != 0) {
        mbedtls_printf("md_string failed: %d", ret);
        goto exit;
    }
    ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,MBEDTLS_MD_SHA256, 20, hash, input_info->sig);
    if (ret != 0) {
        mbedtls_printf("mbedtls_rsa_pkcs1_verify returned -0x%0x\n", (unsigned int) -ret);
        goto exit;
    }
    mbedtls_printf("\nOK (the signature is valid)\n");
    exit_code = EXIT_SUCCESS;
exit:
    // no need to fill output
    *output_len = 0;

    mbedtls_rsa_free(&rsa);
    return exit_code;
}

int main(int argc, const char* argv[]) {
    mbedtls_printf("Entering main()\n");

    return 0;
}

int md_string(const mbedtls_md_info_t *md_info, const unsigned char *buf, size_t n, unsigned char *output) {
    int ret = -1;
    mbedtls_md_context_t ctx;

    if (md_info == NULL)
        return (MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    mbedtls_md_init(&ctx);

    if ((ret = mbedtls_md_setup(&ctx, md_info, 0)) != 0)
        goto cleanup;

    if ((ret = mbedtls_md_starts(&ctx)) != 0)
        goto cleanup;

    if ((ret = mbedtls_md_update(&ctx, buf, n)) != 0)
        goto cleanup;

    ret = mbedtls_md_finish(&ctx, output);

    cleanup:
    mbedtls_md_free(&ctx);
    return ret;
}

void mbedtls_mpi_dump(const char *prefix, const mbedtls_mpi *X) {
    (void)prefix;
    size_t n;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[MBEDTLS_MPI_RW_BUFFER_SIZE];
    memset(s, 0, sizeof(s));

    mbedtls_mpi_write_string(X, 16, s, sizeof(s) - 2, &n);
    printf("%s%s\n", prefix, s);
}

