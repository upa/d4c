# Makefile


CC = gcc -g -Wall
PROGNAME = d4c


all: $(PROGNAME)

.c.o:
	$(CC) -c $< -o $@

d4c: patricia.o d4c.c 
	$(CC) d4c.c -o $@ -lpthread patricia.o

clean:
	rm *.o
	rm $(PROGNAME)
