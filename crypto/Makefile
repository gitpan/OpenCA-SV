#!/bin/sh
#
# OpenCA PKCS#7 Sign/Verify Tool
#

TOP = ..
INCLUDE = $(INCLUDE) -I$(TOP) -I$(TOP)/include
CRYPTO_LIB = $(CRYPTO_LIB)
CC = $(CC)

SRC = callback.c verify.c sign.c verify-tools.c sign2nd.c

all: 
	@for i in $(SRC) ; \
	do \
		echo "$(CC) $(INCLUDE) -I$(TOP)/include -c $$i" ; \
		$(CC) $(INCLUDE) -I$(TOP)/include -c $$i ; \
	done

clean:
	rm -f *.o

