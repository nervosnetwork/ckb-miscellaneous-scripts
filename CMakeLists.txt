cmake_minimum_required(VERSION 3.12)
project(ckb_miscellaneous_scripts C)

set(CMAKE_C_STANDARD 11)
# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")

add_definitions(-DCKB_SIMULATOR)
add_definitions(-D__SHARED_LIBRARY__)
add_definitions(-DCKB_DECLARATION_ONLY)
add_definitions(-DCKB_USE_SIM)


include_directories(deps/ckb-c-stdlib/simulator)
include_directories(deps/ckb-c-stdlib)
# include_directories(deps/ckb-c-stdlib/libc)
# on simulator, we don't use own "libc"
include_directories(deps)
include_directories(deps/ckb-c-stdlib/molecule)
include_directories(c)
include_directories(build)
include_directories(deps/secp256k1/src)
include_directories(deps/secp256k1)
include_directories(deps/mbedtls)
include_directories(deps/mbedtls/include)

add_library(ckb_simulator
        build/secp256k1_data_info.h
        deps/ckb-c-stdlib/simulator/ckb_syscall_simulator.h
        deps/ckb-c-stdlib/simulator/ckb_syscall_simulator.c
        deps/ckb-c-stdlib/simulator/cJSON.h
        deps/ckb-c-stdlib/simulator/cJSON.c
        deps/ckb-c-stdlib/simulator/molecule_decl_only.h deps/ckb-c-stdlib/simulator/blake2b_decl_only.h)

add_executable(sighash_all c/secp256k1_blake2b_sighash_all_dual.c)
target_link_libraries(sighash_all ckb_simulator)

add_executable(sudt c/simple_udt.c deps/ckb-c-stdlib/simulator/blake2b_imp.c)
target_link_libraries(sudt ckb_simulator)

add_library(mbedtls
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

add_executable(rsa_sighash_all deps/ckb-c-stdlib/simulator/rsa_sighash_all_usesim.c c/rsa_sighash_all.h)
target_compile_definitions(rsa_sighash_all PUBLIC -D_FILE_OFFSET_BITS=64 -DCKB_DECLARATION_ONLY)
target_include_directories(rsa_sighash_all PUBLIC deps/ckb-c-stdlib/libc)
target_link_libraries(rsa_sighash_all mbedtls)
