#!/bin/sh

WORKSPACE_DIR = $(PWD)/../..

all: build
.PHONY : all

build: chiapos chiabls

chiapos:
	$(eval TEMP_DIR := $(shell mktemp -d))
	git clone https://github.com/Chia-Network/chiapos.git $(TEMP_DIR)
	@cd ${TEMP_DIR} && \
		git checkout 7e61e21b6443646da0b66d519a5109c378ea104c && \
		patch -p1 < $(WORKSPACE_DIR)/depends/patches/chiapos/001-build-as-static-library.patch && \
		patch -p1 < $(WORKSPACE_DIR)/depends/patches/chiapos/002-fix-build-mingw64.patch && \
		patch -p1 < $(WORKSPACE_DIR)/depends/patches/chiapos/003-add-apis.patch && \
		cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local && \
		make DESTDIR=$(PWD) install
	@rm -rf $(TEMP_DIR)

chiabls:
	$(eval TEMP_DIR := $(shell mktemp -d))
	git clone https://github.com/Chia-Network/bls-signatures.git $(TEMP_DIR)
	@cd ${TEMP_DIR} && \
		git checkout fe7112fc3d20454d7ab0d1c9abee0bf28afeb196 && \
		git apply $(WORKSPACE_DIR)/depends/patches/chiabls/001-build-as-static-library.patch && \
		cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0 -DSODIUM_DISABLE_TESTS=1 . && \
		make DESTDIR=$(PWD) install
	@rm -rf $(TEMP_DIR)

clean:
	rm -rf ./usr
