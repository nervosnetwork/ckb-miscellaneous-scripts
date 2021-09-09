cmake_minimum_required(VERSION 3.17)
project(blst-simulator C)

set(CMAKE_C_STANDARD 11)

# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")

include_directories(../../deps/blst/src)
include_directories(../../deps/blst/bindings)
add_definitions(-DCKB_USE_SIM)

add_executable(simulator main.c ../../deps/blst/src/server.c)
