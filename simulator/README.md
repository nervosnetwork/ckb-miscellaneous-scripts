
# Simulator
The target of simulator is to compile, run code (which will be run on CKB-VM) on any OS and PC.
The we can use our favorite IDE and OS. It can only speed up development but don't skip necessary steps like testing on real CKB-VM.

## Changes
There some changes:
- All contents under simulator folder
- All code enabled by CKB_SIMULATOR macro

If you don't want to use the simulator feature, just ignore the folder.

## How to run
See more in run-simulator.sh script. 

For rsa_sighash_all.c it has a specific version, can run it by:
```bash
cd simulator
mkdir -p build
make
```
## How to get json file
Dump json using [ckb-transaction-dumper](https://github.com/xxuejie/ckb-transaction-dumper). We need a running mainnet
on local machine to dump json. In the following example,  we named the dumped json: "original.json".

Then write a root json file manually (named it data.json):
```json
{
  "is_lock_script": true,
  "script_index": 0,
  "main": "0xa98c212cf055cedbbb665d475c0561b56c68ea735c8aa830c493264effaf18bd",
  "0xa98c212cf055cedbbb665d475c0561b56c68ea735c8aa830c493264effaf18bd": "original.json"
}
```
* is_lock_script, the script to run is "lock" script or "type" script
* script_index, the index of the script in "input"
* main, the tx hash of the dumped json
* "tx_hash": the file name of the dumped json. The key part should be same as the value part of "main".

It might be possible to extend this json to support more TX data.


When run the executables, pass this json file name (data.json, not original.json) as first arguments. 
See more in simulator/run-simulator.sh :

```bash
../build.simulator/sighash_all data.json
../build.simulator/sighash_all data2.json
../build.simulator/sighash_all data3.json
../build.simulator/sudt sudt_data.json
``` 
 
There are more example data under simulator/data folder.


## Used as a library
The simulator is also compiled into library. After build, we can find
library file "libckb_simulator.a". (location simulator/build.simulator/libckb_simulator.a). 
It must be used together with following files and macro:
- simulator/ckb_syscall_simulator.h
- optional simulator/blake2b_imp.c file
- macro: CKB_SIMULATOR, see example in secp256k1_blake2b_sighash_all_dual.c



Explanation of extra blake2b_imp.c file: Some contracts include implementation of blake2b directly 
but some don't. So we don't include implementation of blake2b source in library.
For example, simple_udt doesn't include it so we need to add it to project manually.
