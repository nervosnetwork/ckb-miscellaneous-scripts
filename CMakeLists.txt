cmake_minimum_required(VERSION 3.15)
project(ckb_miscellaneous_scripts C)

set(CMAKE_C_STANDARD 11)

add_definitions(-DSIMULATOR)
add_definitions(-D__SHARED_LIBRARY__)
add_definitions(-DCKB_DECLARATION_ONLY)

include_directories(simulator)
include_directories(deps/ckb-c-stdlib)
# include_directories(deps/ckb-c-stdlib/libc)
# on simulator, we don't use own "libc"
include_directories(deps)
include_directories(deps/ckb-c-stdlib/molecule)
include_directories(c)
include_directories(build)
include_directories(deps/secp256k1/src)
include_directories(deps/secp256k1)


add_executable(sighash_all
        c/secp256k1_blake2b_sighash_all_dual.c
        build/secp256k1_data_info.h
        simulator/ckb_syscall_simulator.h
        simulator/ckb_syscall_simulator.c
        simulator/cJSON.h
        simulator/cJSON.c
        )
