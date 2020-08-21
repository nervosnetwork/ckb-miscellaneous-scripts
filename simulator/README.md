
# Simulator
The target of simulator is to compile, run smart contract on any OS and PC which has good IDE.
The we can use our favorite IDE and OS. It's recommended to test on dev chain when finished.

## Preparation
```Bash
cd deps/secp256k1
./autogen.sh
./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery
make
```
Make sure there is a file named ".libs/libsecp256k1.a" generated.

## IDE 
You can use any IDE based on CMake file. CLion is a very good choice.

## 
