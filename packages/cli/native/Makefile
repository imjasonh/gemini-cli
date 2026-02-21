# Copyright 2025 Google LLC
# SPDX-License-Identifier: Apache-2.0

CC ?= gcc
CC_AMD64 ?= x86_64-linux-gnu-gcc
CC_ARM64 ?= aarch64-linux-gnu-gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror -pedantic -std=c11
LDFLAGS ?= -static

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all clean install cross

all: landlock-helper

landlock-helper: landlock-helper.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

cross: landlock-helper-amd64 landlock-helper-arm64

landlock-helper-amd64: landlock-helper.c
	$(CC_AMD64) $(CFLAGS) $(LDFLAGS) -o $@ $<

landlock-helper-arm64: landlock-helper.c
	$(CC_ARM64) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f landlock-helper landlock-helper-amd64 landlock-helper-arm64

install: landlock-helper
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 landlock-helper $(DESTDIR)$(BINDIR)/landlock-helper
