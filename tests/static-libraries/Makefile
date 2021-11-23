TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
AR := $(TARGET)-ar

OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -nostdinc -nostdlib -nostartfiles -fvisibility=hidden \
	-I ../../include -I ../../deps/ckb-c-stdlib/libc -I ../../deps/ckb-c-stdlib/molecule -I ../../deps/ckb-c-stdlib

LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all: ../../build/test_static_lib

all-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code/tests/static-libraries && make"

../../build/test_static_lib: test_static_lib.c
	$(CC) -DCKB_DECLARATION_ONLY $(CFLAGS) $(LDFLAGS) -o $@ $^ ../../build/librsa_secp256k1.a

clean:
	rm -f ../../build/test_static_lib

dist: clean all

.PHONY: all all-via-docker dist clean fmt
