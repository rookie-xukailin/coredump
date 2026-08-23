#!/usr/bin/env bash
# 三架构交叉编译 libsqlite3.so / liblmdb.so（供新案例链接）
set -u
W=/tmp/coredump_work
T=$W/third
B=$W/build
mkdir -p $B

build() {  # build <tag> <cc>
    local tag=$1 cc=$2
    echo "==== $tag: libsqlite3.so ===="
    $cc $T/sqlite/sqlite3.c -o $B/libsqlite3_${tag}.so -shared -fPIC \
        -g -O0 -fno-omit-frame-pointer \
        -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_LOAD_EXTENSION=0 \
        -lpthread -lm 2>&1 | tail -3
    echo "==== $tag: liblmdb.so ===="
    $cc $T/lmdb/mdb.c $T/lmdb/midl.c -o $B/liblmdb_${tag}.so -shared -fPIC \
        -g -O0 -fno-omit-frame-pointer -lpthread 2>&1 | tail -3
}
build arm64 aarch64-linux-gnu-gcc
build arm32 arm-linux-gnueabihf-gcc
build rv64 riscv64-linux-gnu-gcc

ls -la $B/libsqlite3_*.so $B/liblmdb_*.so
