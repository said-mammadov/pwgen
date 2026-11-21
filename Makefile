CC      ?= gcc
CFLAGS  ?= -O2 -std=c11 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDLIBS  = -lm
PREFIX  ?= /usr/local

pwgen: pwgen.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

install: pwgen
	install -D -m 755 pwgen $(DESTDIR)$(PREFIX)/bin/pwgen

clean:
	rm -f pwgen

.PHONY: install clean
