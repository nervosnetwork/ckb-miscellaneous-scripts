

CFLAGS	?= -g
WARNING_CFLAGS ?=  -Wall -Wextra
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../deps/mbedtls/include -D_FILE_OFFSET_BITS=64 -I../deps/ckb-c-stdlib/libc -DUSE_SIM -DCKB_DECLARATION_ONLY
LOCAL_LDFLAGS =

OBJDIR = build
SRCDIR = ../deps/mbedtls/library

OBJS_CRYPTO= \
	     $(OBJDIR)/aes.o \
	     $(OBJDIR)/aesni.o \
	     $(OBJDIR)/arc4.o \
	     $(OBJDIR)/aria.o \
	     $(OBJDIR)/asn1parse.o \
	     $(OBJDIR)/asn1write.o \
	     $(OBJDIR)/base64.o \
	     $(OBJDIR)/bignum.o \
	     $(OBJDIR)/blowfish.o \
	     $(OBJDIR)/camellia.o \
	     $(OBJDIR)/ccm.o \
	     $(OBJDIR)/chacha20.o \
	     $(OBJDIR)/chachapoly.o \
	     $(OBJDIR)/cipher.o \
	     $(OBJDIR)/cipher_wrap.o \
	     $(OBJDIR)/cmac.o \
	     $(OBJDIR)/ctr_drbg.o \
	     $(OBJDIR)/des.o \
	     $(OBJDIR)/dhm.o \
	     $(OBJDIR)/ecdh.o \
	     $(OBJDIR)/ecdsa.o \
	     $(OBJDIR)/ecjpake.o \
	     $(OBJDIR)/ecp.o \
	     $(OBJDIR)/ecp_curves.o \
	     $(OBJDIR)/entropy.o \
	     $(OBJDIR)/entropy_poll.o \
	     $(OBJDIR)/error.o \
	     $(OBJDIR)/gcm.o \
	     $(OBJDIR)/havege.o \
	     $(OBJDIR)/hkdf.o \
	     $(OBJDIR)/hmac_drbg.o \
	     $(OBJDIR)/md.o \
	     $(OBJDIR)/md2.o \
	     $(OBJDIR)/md4.o \
	     $(OBJDIR)/md5.o \
	     $(OBJDIR)/memory_buffer_alloc.o \
	     $(OBJDIR)/nist_kw.o \
	     $(OBJDIR)/oid.o \
	     $(OBJDIR)/padlock.o \
	     $(OBJDIR)/pem.o \
	     $(OBJDIR)/pk.o \
	     $(OBJDIR)/pk_wrap.o \
	     $(OBJDIR)/pkcs12.o \
	     $(OBJDIR)/pkcs5.o \
	     $(OBJDIR)/pkparse.o \
	     $(OBJDIR)/pkwrite.o \
	     $(OBJDIR)/platform.o \
	     $(OBJDIR)/platform_util.o \
	     $(OBJDIR)/poly1305.o \
	     $(OBJDIR)/psa_crypto.o \
	     $(OBJDIR)/psa_crypto_se.o \
	     $(OBJDIR)/psa_crypto_slot_management.o \
	     $(OBJDIR)/psa_crypto_storage.o \
	     $(OBJDIR)/psa_its_file.o \
	     $(OBJDIR)/ripemd160.o \
	     $(OBJDIR)/rsa.o \
	     $(OBJDIR)/rsa_internal.o \
	     $(OBJDIR)/sha1.o \
	     $(OBJDIR)/sha256.o \
	     $(OBJDIR)/sha512.o \
	     $(OBJDIR)/threading.o \
	     $(OBJDIR)/timing.o \
	     $(OBJDIR)/version.o \
	     $(OBJDIR)/version_features.o \
	     $(OBJDIR)/xtea.o \
	     # This line is intentionally left blank

.PHONY: all clean

all: $(OBJDIR)/libmbedcrypto.a $(OBJDIR)/rsa_sighash_all_usesim
	

# crypto
$(OBJDIR)/libmbedcrypto.a: $(OBJS_CRYPTO)
	echo "  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_CRYPTO)

$(OBJDIR)/rsa_sighash_all_usesim: ../deps/ckb-c-stdlib/libc/src/impl.c ../c/rsa_sighash_all.c rsa_sighash_all_usesim.c $(OBJDIR)/libmbedcrypto.a
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(LOCAL_LDFLAGS) $(LDFLAGS) rsa_sighash_all_usesim.c $(OBJDIR)/libmbedcrypto.a -o $@

run: $(OBJDIR)/rsa_sighash_all_usesim
	$(OBJDIR)/rsa_sighash_all_usesim

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

clean:
	rm -f ./build/* || exit 0
