# base line

[pprof file](./secp256r1_blake160_sighash_lay2dev_bench.pprof)

[flamegraph](./secp256r1_blake160_sighash_lay2dev_bench.svg)

`ckb-debugger --bin build/secp256r1_blake160_sighash_lay2dev_bench --max-cycles 700000000000 --pprof ./temp/libecc-optimization/secp256r1_blake160_sighash_lay2dev_bench.pprof`

Run result: 0
Total cycles consumed: 140538679(134.0M)
Transfer cycles: 55010(53.7K), running cycles: 140483669(134.0M)

Run result: Ok(0)
Total cycles consumed: 140538679(134.0M)
Transfer cycles: 55010(53.7K), running cycles: 140483669(134.0M)

`python folder.old.py < ./temp/libecc-optimization/secp256r1_blake160_sighash_lay2dev_bench.pprof`

total cycles: 134.0 M
nn_set_wlen: 28 %
_nn_mul_redc1: 21 %
nn_init: 12 %
nn_cnd_swap: 6 %
nn_cmp: 5 %
nn_cnd_sub: 4 %
nn_check_initialized: 4 %
nn_copy: 2 %
wclz: 2 %
_nn_cnd_add: 2 %
nn_rshift_fixedlen: 0 %
fp_check_initialized: 0 %
