# Copyright 2025 Google LLC
# SPDX-License-Identifier: Apache-2.0

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror -pedantic -std=c11
LDFLAGS ?= -static

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all clean install

all: landlock-helper

landlock-helper: landlock-helper.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f landlock-helper

install: landlock-helper
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 landlock-helper $(DESTDIR)$(BINDIR)/landlock-helper
