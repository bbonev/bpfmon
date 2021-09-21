# Copyright © 2015-2020 Boian Bonev (bbonev@ipacct.com) {{{
#
# SPDX-License-Identifer: GPL-2.0-or-later
#
# This file is part of bpfmon - traffic monitor for BPF and iptables
#
# bpfmon is free software, released under the terms of GNU General Public License v2.0 or later
#
# }}}

all: bpfmon psort

DEBUG:=-DDEBUG=1 -O0 -g3 -fno-inline -fstack-protector-all
DEBUG:=-O3

PKG_CONFIG?=pkg-config
YASCC?=$(shell $(PKG_CONFIG) --cflags yascreen)
YASLD?=$(shell $(PKG_CONFIG) --libs yascreen)
ifeq ("$(YASLD)","")
YASCC:=
YASLD:=-lyascreen
endif
PCACC?=$(shell $(PKG_CONFIG) --cflags libpcap)
PCALD?=$(shell $(PKG_CONFIG) --libs libpcap)
ifeq ("$(PCALD)","")
PCACC:=
PCALD:=-lpcap
endif

VER=$(shell grep Revision bpfmon.c|head -n1|sed -e 's/.\+Revision: \([0-9.]\+\) \+.\+/\1/')

ifeq ($(CC),tcc)
CCOPT:=-Wall
else
ifeq ($(CC),clang)
CCOPT:=-Wall -Wextra -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 --std=gnu89 -fPIE
else
ifeq ($(shell uname -s),OpenBSD)
ifeq ($(CC),cc)
CC:=egcc
endif
endif
CCOPT:=-Wall -Wextra -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 --std=gnu89 -fPIE
endif
endif

ifndef NO_FLTO
ifeq ($(CC),egcc)
CCOPT+=-flto
endif
ifeq ($(shell uname -s),Linux)
ifeq ($(CC),cc)
CCOPT+=-flto
endif
ifeq ($(CC),gcc)
CCOPT+=-flto
endif
endif
endif

MYCFLAGS=$(DEBUG) $(CPPFLAGS) $(CFLAGS) $(YASCC) $(PCACC) $(CCOPT)
MYLIBS:=$(LIBS) $(YASLD) $(PCALD)
MYLDFLAGS:=$(LDFLAGS) -fPIE -pie

STRIP?=strip
INSTALL?=install

bpfmon.o: bpfmon.c
	$(CC) $(MYCFLAGS) -c bpfmon.c -o bpfmon.o

bpfmon: bpfmon.o
	$(CC) $(MYCFLAGS) $(MYLDFLAGS) -o bpfmon bpfmon.o $(MYLIBS)

psort.o: psort.c
	$(CC) $(MYCFLAGS) -c psort.c -o psort.o

psort: psort.o
	$(CC) $(MYCFLAGS) $(MYLDFLAGS) -o psort psort.o $(MYLIBS)

clean:
	rm -f bpfmon bpfmon.o psort psort.o

install: bpfmon
	$(INSTALL) -TD -m 0755 $< $(DESTDIR)$(PREFIX)/sbin/$<
	$(STRIP) $(DESTDIR)$(PREFIX)/sbin/$<

mkotar:
	$(MAKE) clean
	-dh_clean
	tar \
		--xform 's,^[.],bpfmon-$(VER),' \
		--exclude ./.git \
		--exclude ./.gitignore \
		--exclude ./.cvsignore \
		--exclude ./CVS \
		--exclude ./debian \
		--exclude ./fedora/CVS \
		--exclude ./.sample/CVS \
		-Jcvf ../bpfmon_$(VER).orig.tar.xz .
	-rm -f ../bpfmon_$(VER).orig.tar.xz.asc
	gpg -a --detach-sign ../bpfmon_$(VER).orig.tar.xz
	cp -fa ../bpfmon_$(VER).orig.tar.xz ../bpfmon-$(VER).tar.xz
	cp -fa ../bpfmon_$(VER).orig.tar.xz.asc ../bpfmon-$(VER).tar.xz.asc

