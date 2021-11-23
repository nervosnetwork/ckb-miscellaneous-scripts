### Introduction
Build a static library including several 3-rd party libraries. Then provide it to rust to integrate via FFI.


### Build
```bash
make static-via-docker
```
Then it can be used as static library. Here is the testing:
```bash
make -f tests/static-libraries/Makefile all-via-docker
```
Don't run it, compiling only. The warning can be ignored:
```text
/riscv/lib/gcc/riscv64-unknown-linux-gnu/9.2.0/../../../../riscv64-unknown-linux-gnu/bin/ld: 
warning: cannot find entry symbol _start; not setting start address
```

### Usage
In Rust, include the library by add the following code in `build.rs`:
```Rust
    // link against "rsa_secp256k1" lib (librsa_secp256k1.a)
    println!("cargo:rustc-link-search=native=./build/");
    println!("cargo:rustc-link-lib=static=rsa_secp256k1");
```
See [example](https://github.com/nervosnetwork/ckb-std/pull/12/commits/6ddf0e4d890657ac49dcde5b930ad6a933320366)

Then it can be used in Rust via FFI. Here is an example:
```Rust
#[link(name = "dl-c-impl")]
extern "C" {
    fn ckb_smt_verify(root: * const u8, smt_pair_len: u32, keys: *const u8, 
                      values: * const u8,  proof: *const u8, proof_length: u32);
}
```
