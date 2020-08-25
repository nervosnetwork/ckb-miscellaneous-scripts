
# Simulator
The target of simulator is to compile, run code (which will be run on CKB-VM) on any OS and PC which has good IDE.
The we can use our favorite IDE and OS. It can only speed up development but don't skip necessary steps like testing on real CKB-VM.

## Related Changes
There are 3 changes related to simulator:
- CMakeLists.txt on root
- All contents under simulator folder. For example, stub functions.
- Macro USE_SIM, which is defined in CMakeLists.txt and used in source code.

If you don't want to use the simulator feature, just ignore the 3 items mentioned above.


## Preparation
If the target need 3rd part libraries, like "deps/secp256k1" , you need to compile it on local environment first.
For example, you can build  "deps/secp256k1" as following:
```Bash
cd deps/secp256k1
./autogen.sh
./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery
make
```
Make sure there is a file named ".libs/libsecp256k1.a" generated. 

For mbedtls, you don't need to build: it is manually included in CMakeLists.txt.

## IDE 
You can use any IDE based on CMake file. For example, you can use the following code on Windows:
```bash
mkdir build
cd build
cmake -G "Visual Studio 2017"
```
Then you can open the project by Visual Studio 2017.

