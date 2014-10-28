# Makefile


CC = gcc -g -Wall
PROGNAME = d4c repgen


all: $(PROGNAME)

.c.o:
	$(CC) -c $< -o $@

d4c: patricia.o d4c.c 
	$(CC) d4c.c -o $@ -lpthread patricia.o

repgen: repgen.c
	$(CC) repgen.c -o repgen -lpthread

clean:
	rm *.o
	rm $(PROGNAME)
