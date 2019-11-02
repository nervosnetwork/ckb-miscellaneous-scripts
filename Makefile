TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
CFLAGS := -O3 -I deps -I deps/molecule -I c -I build -I deps/secp256k1/src -I deps/secp256k1 -Wall -Werror -Wno-nonnull-compare -Wno-unused-function
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-s
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h
MOLC := moleculec
MOLC_VERSION := 0.4.1
PROTOCOL_HEADER := build/protocol.h
PROTOCOL_SCHEMA := build/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol

# docker pull nervos/ckb-riscv-gnu-toolchain:bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:52b4f0da101d7cffe1ce5ac1e3cdad44887e9ddc89afa55aa6d0a05ebcd42408

all: build/htlc

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

build/htlc: c/htlc.c build/secp256k1_data_info.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: deps/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc $(CFLAGS) -o $@ $<

$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

generate-protocol: check-moleculec-version ${PROTOCOL_HEADER}

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

fmt:
	clang-format -i -style=Google $(wildcard c/*)
	git diff --exit-code $(wildcard c/*)

${PROTOCOL_HEADER}: ${PROTOCOL_SCHEMA}
	${MOLC} --language c --schema-file $< > $@

${PROTOCOL_SCHEMA}:
	wget -O $@ ${PROTOCOL_URL}

install-tools:
	if [ ! -x "$$(command -v "${MOLC}")" ] \
			|| [ "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" != "${MOLC_VERSION}" ]; then \
		cargo install --force --version "${MOLC_VERSION}" "${MOLC}"; \
	fi

clean:
	rm -rf ${PROTOCOL_HEADER} ${PROTOCOL_SCHEMA}
	rm -rf build/htlc build/dump_secp256k1_data build/secp256k1_data build/secp256k1_data_info.h
	cd deps/secp256k1 && [ -f "Makefile" ] && make clean

dist: clean all

.PHONY: all all-via-docker dist clean fmt
.PHONY: generate-protocol check-moleculec-version install-tools
