#!/bin/sh
#
## OpenCA PKCS#7 Makefile - by Massimiliano Pala
## OpenCA Released Software
## All Rights Reserved

TOP = ..
INCLUDE = $(INCLUDE) -I$(TOP) -I$(TOP)/include
CRYPTO_LIB = $(CRYPTO_LIB)
CC = $(CC)
SRC = tools.c example.c sign.c verify.c sv.c

all: 
	@for i in $(SRC) ; do  \
		echo "$(CC) '-DSVERSION="$(VERSION)"' $(INCLUDE) -I$(TOP)/include -c $$i" ; \
		$(CC) '-DSVERSION="$(VERSION)"' $(INCLUDE) -I$(TOP)/include -c $$i ; \
	done

clean:
	rm -f *.o

