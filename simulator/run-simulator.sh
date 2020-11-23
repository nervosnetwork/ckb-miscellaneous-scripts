#!/bin/bash

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p build.simulator
cd build.simulator
cmake -DCMAKE_C_COMPILER=clang ../..
make all
cd ../data
../build.simulator/sighash_all data.json
../build.simulator/sighash_all data2.json
../build.simulator/sighash_all data3.json
../build.simulator/sudt sudt_data.json
../build.simulator/rsa_sighash_all
