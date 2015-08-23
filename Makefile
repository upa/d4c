# Makefile


CC = gcc -g -Wall
PROGNAME = d3c d4c repgen
INSTALL = /usr/bin/install
INSTALLDST = /usr/local/bin

all: $(PROGNAME)

.c.o:
	$(CC) -c $< -o $@

d4c: patricia.o d4c.c 
	$(CC) d4c.c -o $@ -lpthread patricia.o -DZEROCOPY

d3c: patricia.o d3c.c 
	$(CC) d3c.c -o $@ -lpthread patricia.o

repgen: repgen.c
	$(CC) repgen.c -o repgen -lpthread

install: d4c
	$(INSTALL) -m 744 -o root -g root d4c $(INSTALLDST)/d4c

clean:
	if [ -f $(INSTALLDST)/d4c ]; then	\
		rm -f $(INSTALLDST)/d4c;	\
	fi
	rm -f *.o
	rm -f $(PROGNAME)
