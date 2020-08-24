// # rsa_sighash_all
// same as secp256k1_blake2b_sighash_all_dual but with RSA (mbedtls)
#include <stdlib.h>
#include <string.h>
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "rsa_sighash_all.h"

#define CKB_SUCCESS 0
#define ERROR_ARGUMENTS_LEN (-1)
#define ERROR_ENCODING (-2)
#define ERROR_SYSCALL (-3)
#define ERROR_RSA_INVALID_PARAM1 (-40)
#define ERROR_RSA_INVALID_PARAM2 (-41)
#define ERROR_RSA_MDSTRING_FAILED (-42)
#define ERROR_RSA_VERIFY_FAILED (-43)
#define ERROR_RSA_ONLY_INIT (-44)


#define CHECK_PARAM(cond, code) do {if (!(cond)) {exit_code = code; goto exit;}} while(0)

#if defined(USE_SIM)
#include <stdio.h>
#define mbedtls_printf printf
#else
#define mbedtls_printf(x, ...)  (void)0
#endif

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

/**
 *
 * @param prefilled_data ignore. Not used.
 * @param signature_buffer pointer to signature buffer. It is casted to type "RsaInfo*"
 * @param signature_size size of signature_buffer. it should be exactly the same as size of "RsaInfo".
 * @param message_buffer pointer to message buffer.
 * @param message_size size of message_buffer.
 * @param output ignore. Not used
 * @param output_len ignore. Not used.
 * @return
 */
__attribute__((visibility("default"))) int validate_signature(
        void *prefilled_data, const uint8_t *signature_buffer,
        size_t signature_size, const uint8_t *message_buffer, size_t message_size,
        uint8_t *output, size_t *output_len) {
    int ret;
    int exit_code = ERROR_RSA_ONLY_INIT;
    mbedtls_rsa_context rsa;
    unsigned char hash[32];
    RsaInfo *input_info = (RsaInfo *) signature_buffer;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    CHECK_PARAM(signature_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
    CHECK_PARAM(message_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
    CHECK_PARAM(signature_size == sizeof(RsaInfo), ERROR_RSA_INVALID_PARAM2);

    mbedtls_mpi_read_binary_le(&rsa.E, (const unsigned char *) &input_info->E, sizeof(uint32_t));
    mbedtls_mpi_read_binary_le(&rsa.N, (const unsigned char *) input_info->N, input_info->key_size / 8);
    rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

    ret = md_string(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), message_buffer, message_size, hash);
    if (ret != 0) {
        mbedtls_printf("md_string failed: %d", ret);
        exit_code = ERROR_RSA_MDSTRING_FAILED;
        goto exit;
    }
    // note: hashlen = 20 is used for MD5, we can ignore it here for SHA256.
    ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 20, hash, input_info->sig);
    if (ret != 0) {
        mbedtls_printf("mbedtls_rsa_pkcs1_verify returned -0x%0x\n", (unsigned int) -ret);
        exit_code = ERROR_RSA_VERIFY_FAILED;
        goto exit;
    }
    mbedtls_printf("\nOK (the signature is valid)\n");
    exit_code = CKB_SUCCESS;

exit:
    mbedtls_rsa_free(&rsa);
    return exit_code;
}

#if defined(USE_SIM) || defined(RSA_RUN_TEST)

static unsigned char get_hex(unsigned char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else
        return 0;
}

static int scan_hex(const char *s, unsigned char *value) {
    if (s[0] == '\0' || s[1] == '\0')
        return 0;

    unsigned char high_part = get_hex(s[0]);
    unsigned char low_part = get_hex(s[1]);

    *value = (high_part << 4) + low_part;
    return 1;
}

void mbedtls_mpi_dump(const char *prefix, const mbedtls_mpi *X) {
    size_t n;
    char s[1024];
    memset(s, 0, sizeof(s));

    mbedtls_mpi_write_string(X, 16, s, sizeof(s) - 2, &n);
    mbedtls_printf("%s%s\n", prefix, s);
}


int main(int argc, const char *argv[]) {
    mbedtls_printf("Entering main()\n");
    const char *sig = "5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF482546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE48206DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C73D1EE248819479574028389376BD7F9FB4F5C9B";
    const char *msg = "hello,CKB!";
    unsigned char sig_buf[MBEDTLS_MPI_MAX_SIZE];
    const char *N = "A1D46FBA2318F8DCEF16C280948B1CF27966B9B47225ED2989F8D74B45BD36049C0AAB5AD0FF003553BA843C8E12782FC5873BB89A3DC84B883D25666CD22BF3ACD5B675969F8BEBFBCAC93FDD927C7442B178B10D1DFF9398E52316AAE0AF74E594650BDC3C670241D418684593CDA1A7B9DC4F20D2FDC6F66344074003E211";
    // convert signature in plain string to binary
    size_t i = 0;
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

    RsaInfo info;
    info.key_size = 1024;
    info.sig = sig_buf;
    info.E = 65537; // hex format: "010001"
    info.sig_length = sig_len / 2;

    info.N = malloc(info.key_size / 8);
    mbedtls_mpi_write_binary_le(&NN, info.N, info.key_size / 8);

    uint8_t output;
    size_t output_len;
    int result = validate_signature(NULL, (const uint8_t *) &info, sizeof(info), (const uint8_t *)msg, strlen(msg), &output,
                                    &output_len);
    if (result == 0) {
        mbedtls_printf("validate signature passed\n");
    } else {
        mbedtls_printf("validate signature failed: %d\n", result);
    }

    msg = "hello, world!";
    int result2 = validate_signature(NULL, (const uint8_t *) &info, sizeof(info), (const uint8_t *)msg, strlen(msg), &output, &output_len);
    if (result2 == ERROR_RSA_VERIFY_FAILED) {
        mbedtls_printf("validate signature passed\n");
    } else {
        mbedtls_printf("(failed case) validate signature failed:%d\n", result);
    }

    free(info.N);
    if (result == 0 && result2 == ERROR_RSA_VERIFY_FAILED) {
        return 0;
    } else {
        return 1;
    }
}

#else
int main(int argc, const char* argv[]) {
    return 0;
}
#endif

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
