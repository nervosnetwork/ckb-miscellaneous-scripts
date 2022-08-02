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
# taking low hanging fruits
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
```

## short-circuiting some hot code

There are a few hot functions which are short-circuitable. We can return fast in
nn_set_wlen and nn_cnd_swap without doing expensive calculation.

## turning off some checks
Some safety checks seem to be unnecessary for signature verification. We turn off `nn_check_initialized`/`fp_check_initialized`,
as we are sure all `nn`/`fp` are initialized. We also `__attribute__((always_inline)) inline` for even lower overhead
(with minimal intrusion to original code base).

# disabling builtins

The overhead of `memset` (16%) is quite large. The callers of `memset` are mostly `nn_init`. Strangely, we don't call `memset` ourself from `nn_init`.
We use `gdb -batch -ex "file ./build/secp256r1_blake160_sighash_lay2dev_bench" -ex 'disassemble nn_init'` to dump the disassembly code of `nn_init`. We see `nn_init` indeed called `memset`.

```
Dump of assembler code for function nn_init:
   0x0000000000010992 <+0>:     beqz    a0,0x1099c <nn_init+10>
   0x0000000000010994 <+2>:     li      a3,96
   0x0000000000010998 <+6>:     bgeu    a3,a1,0x1099e <nn_init+12>
   0x000000000001099c <+10>:    j       0x1099c <nn_init+10>
   0x000000000001099e <+12>:    addiw   a5,a1,7
   0x00000000000109a2 <+16>:    sraiw   a5,a5,0x3
   0x00000000000109a6 <+20>:    sb      a5,104(a0)
   0x00000000000109aa <+24>:    auipc   a5,0xb
   0x00000000000109ae <+28>:    ld      a5,1566(a5) # 0x1bfc8
   0x00000000000109b2 <+32>:    sd      a5,96(a0)
   0x00000000000109b4 <+34>:    li      a2,96
   0x00000000000109b8 <+38>:    li      a1,0
   0x00000000000109ba <+40>:    j       0x1022e <memset>
End of assembler dump.
```

How so? Further investigation shows it is gcc that automatically inserts memset (see [this comment](https://github.com/riscv-collab/riscv-gnu-toolchain/issues/758#issuecomment-720175645)) into the generated code.
We tried to build the binary without gcc builtins by specifying the flag `-fno-builtin`. The end result is

```
Run result: 0
Total cycles consumed: 18897592(18.0M)
Transfer cycles: 12536(12.2K), running cycles: 18885056(18.0M)
total cycles: 18.0 M
_nn_mul_redc1: 38 %
nn_cmp: 9 %
nn_cnd_sub: 8 %
nn_set_wlen: 8 %
nn_cnd_add: 5 %
nn_init: 5 %
nn_bitlen: 4 %
nn_rshift_fixedlen: 1 %
nn_copy: 1 %
nn_check_initialized: 1 %
nn_mod_sub: 1 %
fp_mul_redc1: 1 %
fp_init: 0 %
nn_uninit: 0 %
nn_mul_redc1: 0 %
nn_mod_add: 0 %
_nn_divrem_normalized: 0 %
nn_modinv_odd: 0 %
nn_cnd_swap: 0 %
fp_sub: 0 %
fp_copy: 0 %
fp_add: 0 %
```

# using gcc extension for word_mul
The function with prevailing costs is `_nn_mul_redc1`. This function used naive hand-written code to compute the product of two word.
Gcc provides a type `__int128` for 128 bit integers. We can directly compute the product of two 64 bit integers
as in this example `unsigned __int128 t = (unsigned __int128)0xffffffffffffffff * 3`.
Using [this commit](https://github.com/contrun/libecc/commit/476a03d629175f059f6b0e7cd08433555bccccfb), we obtained

```
Run result: 0
Total cycles consumed: 15936199(15.2M)
Transfer cycles: 12496(12.2K), running cycles: 15923703(15.2M)
total cycles: 15.2 M
_nn_mul_redc1: 26 %
nn_cmp: 11 %
nn_cnd_sub: 10 %
nn_set_wlen: 9 %
nn_cnd_add: 6 %
nn_init: 6 %
nn_bitlen: 4 %
nn_rshift_fixedlen: 1 %
nn_copy: 1 %
nn_check_initialized: 1 %
nn_mod_sub: 1 %
fp_mul_redc1: 1 %
fp_init: 1 %
nn_uninit: 1 %
nn_mul_redc1: 0 %
```

# replacing Montgomery multiplication implementation

## benchmarking Montgomery multiplication implementations
With `ckb-debugger --bin build/ll_u256_mont_mul` (where [`build/ll_u256_mont_mul`](https://github.com/contrun/ckb-miscellaneous-scripts/blob/secp256r1_blake160_optiomization/c/ll_u256_mont_mul.c) is a simple program to benchmark
[the Montgomery mulitplication algorithm from piggypiggy/fp256](https://github.com/piggypiggy/fp256/blob/master/src/ll/riscv64/ll_u256_mont-riscv64.S)),
we have

```
Run result: 0
Total cycles consumed: 5165491(4.9M)
Transfer cycles: 1796(1.8K), running cycles: 5163695(4.9M)
```

With `ckb-debugger --bin build/libecc_nn_mul_redc1` (where [`build/libecc_nn_mul_redc1`](https://github.com/contrun/ckb-miscellaneous-scripts/blob/secp256r1_blake160_optiomization/c/libecc_nn_mul_redc1.c) is a simple program to benchmark libecc's implemenation of Montgomery multiplication), we have
```
Run result: 0
Total cycles consumed: 18112888(17.3M)
Transfer cycles: 6522(6.4K), running cycles: 18106366(17.3M)
```

## integrating new Montgomery implementation into signature verification

We need to compare the memory represenations of two big number systems. In fp256, a 256 bit number is represented as an array of `uint64_t` numbers,
while in libecc any big number is represented as an array of `u8`s (`unsigned char`s).

We need to first check the endianness of `uint64_t`s in an fp256 big number and the endianness of bytes in a `uint64_t`, and then check the endianness of `u8`s in a libecc big number.
Fortunately, riscv is little-endian, both `uint64_t`s in an fp256 big number and `u8`s in a libecc big number are little endian.
That is to say, we need only to copy (or set) memory from two implementations.
We may just replace libecc `_nn_mul_redc1` with

```
static void _nn_mul_redc1(nn_t out, nn_src_t in1, nn_src_t in2, nn_src_t p,
			  word_t mpinv) {
  ll_u256_mont_mul(out->val, in1->val, in2->val, p->val, mpinv);
}

```

Unfortunately, not so fast. There is another small problem. The code above would run forever.
The memory representation of a big number in libecc is defined as a `nn`, which is
```
typedef struct {
  word_t val[BIT_LEN_WORDS(NN_MAX_BIT_LEN)];
  word_t magic;
  u8 wlen;
} nn;
```
There is some redundant information (`wlen`, word length of this big number) embedded in this struct.
We need to initialize the `wlen` of the multiplication result with `nn_set_wlen(out, p->wlen)`.
Then, we are good to go.

```
Run result: 0
Total cycles consumed: 14407842(13.7M)
Transfer cycles: 14130(13.8K), running cycles: 14393712(13.7M)
total cycles: 13.7 M
nn_mul_redc1: 24 %
nn_set_wlen: 10 %
nn_cmp: 10 %
nn_cnd_sub: 10 %
nn_cnd_add: 7 %
nn_init: 6 %
nn_bitlen: 5 %
nn_rshift_fixedlen: 2 %
nn_copy: 1 %
nn_mod_sub: 1 %
fp_mul_redc1: 1 %
fp_init: 1 %
nn_check_initialized: 1 %
nn_uninit: 1 %
nn_mod_add: 0 %
nn_modinv_odd: 0 %
nn_cnd_swap: 0 %
```
