PREFIX ?= /usr/local

all: ssmping asmping ssmpingd mcfirst

OBJ = ssmpngcl.o ssmpingc.o

ssmping: $(OBJ) joinch.o
asmping: $(OBJ) joingrp.o
mcfirst: $(OBJ) joinch.o joingrp.o
ssmpingd: $(OBJ)

install: ssmping asmping ssmpingd mcfirst
	install -D ssmping $(DESTDIR)$(PREFIX)/bin/ssmping
	install -D asmping $(DESTDIR)$(PREFIX)/bin/asmping
	install -D ssmpingd $(DESTDIR)$(PREFIX)/bin/ssmpingd
	install -D mcfirst $(DESTDIR)$(PREFIX)/bin/mcfirst
	install -D ssmping.1 $(DESTDIR)$(PREFIX)/man/man1/ssmping.1
	install -D asmping.1 $(DESTDIR)$(PREFIX)/man/man1/asmping.1
	install -D mcfirst.1 $(DESTDIR)$(PREFIX)/man/man1/mcfirst.1

clean:
	rm -f $(OBJ) joinch.o joingrp.o ssmping asmping ssmpingd mcfirst
