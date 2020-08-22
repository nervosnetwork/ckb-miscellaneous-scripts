cmake_minimum_required(VERSION 3.15)
project(ckb-miscellaneous-scripts C)

set(CMAKE_C_STANDARD 11)

add_definitions(-DUSE_SIM)
add_definitions(-DENABLE_TEST)
include_directories(build)
include_directories(c)
include_directories(deps)
include_directories(deps/secp256k1)
include_directories(deps/secp256k1/src)
include_directories(simulator)
include_directories(deps/ckb-c-stdlib/molecule)
include_directories(deps/ckb-c-stdlib)
include_directories(deps/mbedtls/include)

link_directories(deps/secp256k1/.libs)
#link_directories(deps/mbedtls/library)
#link_libraries(libsecp256k1.a)
#link_libraries(libmbedcrypto.a)

set(mbedtls_files
        deps/mbedtls/library/aes.c
        deps/mbedtls/library/aesni.c
        deps/mbedtls/library/arc4.c
        deps/mbedtls/library/aria.c
        deps/mbedtls/library/asn1parse.c
        deps/mbedtls/library/asn1write.c
        deps/mbedtls/library/base64.c
        deps/mbedtls/library/bignum.c
        deps/mbedtls/library/blowfish.c
        deps/mbedtls/library/camellia.c
        deps/mbedtls/library/ccm.c
        deps/mbedtls/library/chacha20.c
        deps/mbedtls/library/chachapoly.c
        deps/mbedtls/library/cipher.c
        deps/mbedtls/library/cipher_wrap.c
        deps/mbedtls/library/cmac.c
        deps/mbedtls/library/ctr_drbg.c
        deps/mbedtls/library/des.c
        deps/mbedtls/library/dhm.c
        deps/mbedtls/library/ecdh.c
        deps/mbedtls/library/ecdsa.c
        deps/mbedtls/library/ecjpake.c
        deps/mbedtls/library/ecp.c
        deps/mbedtls/library/ecp_curves.c
        deps/mbedtls/library/entropy.c
        deps/mbedtls/library/entropy_poll.c
        deps/mbedtls/library/error.c
        deps/mbedtls/library/gcm.c
        deps/mbedtls/library/havege.c
        deps/mbedtls/library/hkdf.c
        deps/mbedtls/library/hmac_drbg.c
        deps/mbedtls/library/md.c
        deps/mbedtls/library/md2.c
        deps/mbedtls/library/md4.c
        deps/mbedtls/library/md5.c
        deps/mbedtls/library/memory_buffer_alloc.c
        deps/mbedtls/library/nist_kw.c
        deps/mbedtls/library/oid.c
        deps/mbedtls/library/padlock.c
        deps/mbedtls/library/pem.c
        deps/mbedtls/library/pk.c
        deps/mbedtls/library/pk_wrap.c
        deps/mbedtls/library/pkcs12.c
        deps/mbedtls/library/pkcs5.c
        deps/mbedtls/library/pkparse.c
        deps/mbedtls/library/pkwrite.c
        deps/mbedtls/library/platform.c
        deps/mbedtls/library/platform_util.c
        deps/mbedtls/library/poly1305.c
        deps/mbedtls/library/psa_crypto.c
        deps/mbedtls/library/psa_crypto_se.c
        deps/mbedtls/library/psa_crypto_slot_management.c
        deps/mbedtls/library/psa_crypto_storage.c
        deps/mbedtls/library/psa_its_file.c
        deps/mbedtls/library/ripemd160.c
        deps/mbedtls/library/rsa.c
        deps/mbedtls/library/rsa_internal.c
        deps/mbedtls/library/sha1.c
        deps/mbedtls/library/sha256.c
        deps/mbedtls/library/sha512.c
        deps/mbedtls/library/threading.c
        deps/mbedtls/library/timing.c
        deps/mbedtls/library/version.c
        deps/mbedtls/library/version_features.c
        deps/mbedtls/library/xtea.c)


set(common_files deps/molecule/molecule_builder.h
        deps/molecule/molecule_reader.h
        simulator/ckb_syscall_sim.c)

add_executable(secp256k1_blake2b_sighash_all_dual
        c/secp256k1_blake2b_sighash_all_dual.c
        ${common_files})

add_executable(rsa_sighash_all
        c/rsa_sighash_all.c
        ${common_files}
        ${mbedtls_files}
        c/rsa_sighash_all.h)
