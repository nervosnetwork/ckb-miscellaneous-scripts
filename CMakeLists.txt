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
link_directories(deps/mbedtls/library)
link_libraries(libsecp256k1.a)
link_libraries(libmbedcrypto.a)

set(common_files deps/molecule/molecule_builder.h
        deps/molecule/molecule_reader.h
        simulator/ckb_syscall_sim.c)

add_executable(secp256k1_blake2b_sighash_all_dual
        c/secp256k1_blake2b_sighash_all_dual.c
        ${common_files})

add_executable(rsa_sighash_all
        c/rsa_sighash_all.c
        ${common_files} c/rsa_sighash_all.h)
