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
    RsaInfo* input_info = (RsaInfo*)signature_buffer;

    // TODO: check buff size
    // TODO: check parameters

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

     mbedtls_mpi_read_binary_le(&rsa.E, (const unsigned char*)&input_info->E, 4);
     // mbedtls_mpi_dump("rsa.E=", &rsa.E);
     mbedtls_mpi_read_binary_le(&rsa.N, (const unsigned char*)&input_info->N, input_info->key_size/8);
     rsa.N.p = input_info->N;
     // note: the unit of .n is mbedtls_mpi_uint, it can be 4 or 8.
     rsa.N.n = input_info->key_size/8/sizeof(mbedtls_mpi_uint);
     rsa.N.s = 1;

#if 0
     // keep this in case we need it for debugging.
//    const char *PRIV_E = "010001";
//    const char *PRIV_N = "A1D46FBA2318F8DCEF16C280948B1CF27966B9B47225ED2989F8D74B45BD36049C0AAB5AD0FF003553BA843C8E12782FC5873BB89A3DC84B883D25666CD22BF3ACD5B675969F8BEBFBCAC93FDD927C7442B178B10D1DFF9398E52316AAE0AF74E594650BDC3C670241D418684593CDA1A7B9DC4F20D2FDC6F66344074003E211";
//    mbedtls_mpi_read_string(&rsa.E, 16, PRIV_E);
//    mbedtls_mpi_dump("rsa.E=", &rsa.E);
//    mbedtls_mpi_read_string(&rsa.N, 16, PRIV_N);
//    mbedtls_mpi_dump("rsa.N=", &rsa.N);

#endif

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


static unsigned char get_hex(unsigned char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else
        return 0;
    // todo: support assert?
}

static int scan_hex(const char* s, unsigned char* value) {
    if (s[0] == '\0' || s[1] == '\0')
        return 0;

    unsigned char high_part = get_hex(s[0]);
    unsigned char low_part = get_hex(s[1]);

    *value =  (high_part << 4) + low_part;
    return 1;
}

int main(int argc, const char* argv[]) {
    mbedtls_printf("Entering main()\n");
    const char* sig = "5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF482546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE48206DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C73D1EE248819479574028389376BD7F9FB4F5C9B";
    const char* msg = "hello,CKB!";
    unsigned char sig_buf[MBEDTLS_MPI_MAX_SIZE];
    const char* N = "A1D46FBA2318F8DCEF16C280948B1CF27966B9B47225ED2989F8D74B45BD36049C0AAB5AD0FF003553BA843C8E12782FC5873BB89A3DC84B883D25666CD22BF3ACD5B675969F8BEBFBCAC93FDD927C7442B178B10D1DFF9398E52316AAE0AF74E594650BDC3C670241D418684593CDA1A7B9DC4F20D2FDC6F66344074003E211";
    const char* E = "010001";
    // convert signature in plain string to binary
    size_t i;
    size_t sig_len = strlen(sig);
    const char *sig_ptr = sig;
    const char *sig_end = sig + sig_len;
    while (1) {
        unsigned char c = 0;
        int consumed = scan_hex(sig_ptr, &c);
        if (consumed == 0)
            break;
        if (i >= (int) sizeof(sig_buf))
            break;
        sig_buf[i++] = (unsigned char) c;
        sig_ptr += consumed * 2;
        if (sig_ptr >= sig_end)
            break;
    }
    mbedtls_mpi NN;
    mbedtls_mpi_read_string(&NN, 16, N);
//    mbedtls_mpi_dump("NN = ", &NN);

//    mbedtls_mpi EE;
//    mbedtls_mpi_read_string(&EE, 16, E);
//    mbedtls_mpi_dump("EE = ", &EE);

    RsaInfo info;
    info.key_size = 1024;
    info.sig = sig_buf;
    info.E = 65537;
    info.N = (uint8_t*)NN.p;
    info.sig_length = sig_len/2;

    uint8_t output;
    size_t output_len;
    int result = validate_signature(NULL, (const uint8_t *)&info, sizeof(info), msg, strlen(msg), &output, &output_len);
    if (result == 0) {
        mbedtls_printf("validate signature passed\n");
    } else {
        mbedtls_printf("validate signature failed: %d\n", result);
    }

    msg = "hello, world!";
    result = validate_signature(NULL, (const uint8_t *)&info, sizeof(info), msg, strlen(msg), &output, &output_len);
    if (result == 1) {
        mbedtls_printf("validate signature passed\n");
    } else {
        mbedtls_printf("(failed case) validate signature failed:%d\n", result);
    }
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
    mbedtls_printf("%s%s\n", prefix, s);
}

