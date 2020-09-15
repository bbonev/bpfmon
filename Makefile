# Copyright © 2015-2020 Boian Bonev (bbonev@ipacct.com) {{{
#
# SPDX-License-Identifer: GPL-2.0-or-later
#
# This file is part of bpfmon - traffic monitor for BPF and iptables
#
# bpfmon is free software, releasead under the terms of GNU General Public License v2.0 or later
#
# }}}

all: bpfmon psort

DEBUG:=-DDEBUG=1 -O0 -g3 -fno-inline -fstack-protector-all
DEBUG:=-O3

LIBS:=-lpcap

VER=$(shell grep Revision bpfmon.c|head -n1|sed -e 's/.\+Revision: \([0-9.]\+\) \+.\+/\1/')

ifeq ($(CC),tcc)
CCOPT:=-Wall -I.
else
ifeq ($(CC),clang)
CCOPT:=-Wall -Wextra -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 -I. --std=gnu89
else
ifeq ($(shell uname -s),OpenBSD)
ifeq ($(CC),cc)
CC:=egcc
endif
endif
CCOPT:=-Wall -Wextra -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 -I. --std=gnu89
endif
endif
ifeq ($(CC),egcc)
CCOPT+=-flto
endif
ifndef NO_FLTO
ifeq ($(shell uname -s),Linux)
ifeq ($(CC),cc)
CCOPT+=-flto
endif
ifeq ($(CC),gcc)
CCOPT+=-flto
endif
endif
endif

MYCFLAGS=$(DEBUG) $(CPPFLAGS) $(CFLAGS) $(CCOPT)
MYLDFLAGS=$(LDFLAGS)

STRIP?=strip

bpfmon.o: bpfmon.c yascreen.h
	$(CC) $(MYCFLAGS) -c bpfmon.c -o bpfmon.o

yascreen.o: yascreen.c yascreen.h
	$(CC) $(MYCFLAGS) -c yascreen.c -o yascreen.o

bpfmon: bpfmon.o yascreen.o
	$(CC) $(MYCFLAGS) -o bpfmon bpfmon.o yascreen.o $(LIBS)
	$(STRIP) bpfmon

bpfmon-shared: bpfmon.o
	$(CC) $(MYCFLAGS) $(MYLDFLAGS) -o bpfmon-shared bpfmon.o $(LIBS) -lyascreen
	$(STRIP) bpfmon-shared

psort.o: psort.c yascreen.h
	$(CC) $(CCOPT) -c psort.c -o psort.o

psort: psort.o yascreen.o
	$(CC) $(CCOPT) -o psort psort.o yascreen.o $(LIBS)
	$(STRIP) psort

clean:
	rm -f bpfmon bpfmon-shared bpfmon.o yascreen.o psort psort.o

install: bpfmon-shared
	$(INSTALL) -TD -m 0755 $< $(DESTDIR)$(PREFIX)/sbin/$<
	$(STRIP) $<

mkotar:
	$(MAKE) clean
	#dh_clean
	tar \
		--exclude ./.git \
		--exclude ./CVS \
		--exclude ./debian/CVS \
		--exclude ./debian/source/CVS \
		-Jcvf ../bpfmon_$(VER).orig.tar.xz .
	-rm -f ../bpfmon_$(VER).orig.tar.xz.asc
	gpg -a --detach-sign ../bpfmon_$(VER).orig.tar.xz

