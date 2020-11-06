cmake_minimum_required(VERSION 3.12)
project(ckb_miscellaneous_scripts C)

set(CMAKE_C_STANDARD 11)
# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")

add_definitions(-DCKB_SIMULATOR)
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

add_library(ckb_simulator
        build/secp256k1_data_info.h
        simulator/ckb_syscall_simulator.h
        simulator/ckb_syscall_simulator.c
        simulator/cJSON.h
        simulator/cJSON.c
        simulator/molecule_decl_only.h simulator/blake2b_decl_only.h)

add_executable(sighash_all c/secp256k1_blake2b_sighash_all_dual.c)
target_link_libraries(sighash_all ckb_simulator)

add_executable(sudt c/simple_udt.c simulator/blake2b_imp.c)
target_link_libraries(sudt ckb_simulator)
