# base line
The benchmark program [secp256r1_blake160_sighash_lay2dev_bench.c](https://github.com/contrun/ckb-miscellaneous-scripts/blob/f954617efcbed7d0aa90086e6d20d3192a1c73b2/c/secp256r1_blake160_sighash_lay2dev_bench.c)
is compiled with `make LIBECC_PATH=/workspace/libecc build/secp256r1_blake160_sighash_lay2dev_bench` using [this Makefile](https://github.com/contrun/ckb-miscellaneous-scripts/blob/f954617efcbed7d0aa90086e6d20d3192a1c73b2/Makefile). The toolchain (contained in a fixed docker image) and compiler flags used are availble in the Makefile, and the libecc commit is [7dbef0ec902db95d4e515b4d9ef15d203f31c243](https://github.com/contrun/libecc/tree/7dbef0ec902db95d4e515b4d9ef15d203f31c243).

## profiling

`ckb-debugger --bin build/secp256r1_blake160_sighash_lay2dev_bench --max-cycles 700000000000 --pprof ./temp/libecc-optimization/secp256r1_blake160_sighash_lay2dev_bench.pprof`

```
Run result: 0
Total cycles consumed: 29765418(28.4M)
Transfer cycles: 12750(12.5K), running cycles: 29752668(28.4M)
```

## generating flamegraph
`inferno-flamegraph > ./temp/libecc-optimization/secp256r1_blake160_sighash_lay2dev_bench.svg < ./temp/libecc-optimization/secp256r1_blake160_sighash_lay2dev_bench.pprof`

[flamegraph](./secp256r1_blake160_sighash_lay2dev_bench.svg)

## showing leaf functions usage

Use [ckb-vm-pprof/folder.py at master · nervosnetwork/ckb-vm-pprof](https://github.com/nervosnetwork/ckb-vm-pprof/blob/master/scripts/folder.py),

`python folder.py < ./temp/libecc-optimization/secp256r1_blake160_sighash_lay2dev_bench.pprof`

```
total cycles: 28.4 M
_nn_mul_redc1: 23 %
nn_set_wlen: 12 %
memset: 12 %
nn_check_initialized: 10 %
nn_cmp: 7 %
nn_cnd_sub: 5 %
nn_cnd_add: 3 %
nn_cnd_swap: 2 %
nn_bitlen: 2 %
fp_check_initialized: 1 %
memcpy: 1 %
nn_init: 1 %
nn_rshift_fixedlen: 1 %
nn_mod_sub: 0 %
fp_mul_redc1: 0 %
fp_init: 0 %
nn_isodd: 0 %
nn_copy: 0 %
nn_uninit: 0 %
nn_mul_redc1: 0 %
nn_zero: 0 %
nn_mod_add: 0 %
```
# low hanging fruits
Inspecting hot functions in `folder.py`, we can fetch some low hanging fruits.

## end result
The libecc commit is [76fd62031ad9f0500725389dae94ef0550af5417](https://github.com/contrun/libecc/tree/76fd62031ad9f0500725389dae94ef0550af5417).
```
Run result: 0
Total cycles consumed: 22577333(21.5M)
Transfer cycles: 12692(12.4K), running cycles: 22564641(21.5M)
total cycles: 21.5 M
_nn_mul_redc1: 31 %
memset: 16 %
nn_cmp: 8 %
nn_cnd_sub: 7 %
nn_set_wlen: 7 %
nn_cnd_add: 4 %
nn_bitlen: 3 %
memcpy: 2 %
nn_init: 2 %
nn_rshift_fixedlen: 1 %
nn_check_initialized: 0 %
nn_mod_sub: 0 %
fp_mul_redc1: 0 %
fp_init: 0 %
nn_uninit: 0 %
nn_mul_redc1: 0 %
nn_copy: 0 %
nn_mod_add: 0 %
_nn_divrem_normalized: 0 %
nn_modinv_odd: 0 %
nn_cnd_swap: 0 %
memmove: 0 %
fp_sub: 0 %
fp_copy: 0 %
fp_add: 0 %
nn_isodd: 0 %
fp_uninit: 0 %
nn_clz: 0 %
fp_check_initialized: 0 %

## short-circuiting some hot code

There are a few hot functions which are short-circuitable. We can return fast in
nn_set_wlen and nn_cnd_swap without doing expensive calculation.

## turning off some checks
Some safety checks seem to be unnecessary for signature verification. We turn off `nn_check_initialized`/`fp_check_initialized`,
as we are sure all `nn`/`fp` are initialized. We also `__attribute__((always_inline)) inline` for even lower overhead
(with minimal intrusion to original code base).
