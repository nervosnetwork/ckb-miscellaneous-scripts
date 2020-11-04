#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p build.simulator
cd build.simulator
cmake ../..
make all
cd ../data
../build.simulator/sighash_all data.json
../build.simulator/sighash_all data2.json
../build.simulator/sighash_all data3.json
../build.simulator/sudt sudt_data.json
