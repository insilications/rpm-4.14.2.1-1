#!/usr/bin/env bash 
sd "/usr/lib64/libz.so" "/usr/lib64/libz.a" $(fd -uu --glob Makefile)
sd "/usr/lib64/liblzma.so" "/usr/lib64/liblzma.a" $(fd -uu --glob Makefile)
sd "/usr/lib64/libzstd.so" "/usr/lib64/libzstd.a" $(fd -uu --glob Makefile)
sd "/usr/lib64/libbz2.so" "/usr/lib64/libbz2.a" $(fd -uu --glob Makefile)
sd "/usr/lib64/libelf.so" "/usr/lib64/libelf.a /usr/lib64/libz.a" $(fd -uu --glob Makefile)
sd "/usr/lib64/libdw.so" "/usr/lib64/libdw.a /usr/lib64/libelf.a /usr/lib64/libz.a /usr/lib64/liblzma.a /usr/lib64/libzstd.a" $(fd -uu --glob Makefile)
sd "/usr/lib64/libcrypto.so" "/usr/lib64/libcrypto.a" $(fd -uu --glob Makefile)
#
sd "\-lz" "/usr/lib64/libz.a" $(fd -uu --glob Makefile)
sd "\-llzma" "/usr/lib64/liblzma.a" $(fd -uu --glob Makefile)
sd "\-lzstd" "/usr/lib64/libzstd.a" $(fd -uu --glob Makefile)
sd "\-lbz2" "/usr/lib64/libbz2.a" $(fd -uu --glob Makefile)
sd "\-lelf" "/usr/lib64/libelf.a /usr/lib64/libz.a" $(fd -uu --glob Makefile)
sd "\-ldw" "/usr/lib64/libdw.a /usr/lib64/libelf.a /usr/lib64/libz.a /usr/lib64/liblzma.a /usr/lib64/libzstd.a" $(fd -uu --glob Makefile)
sd "\-lcrypto" "/usr/lib64/libcrypto.a" $(fd -uu --glob Makefile)
