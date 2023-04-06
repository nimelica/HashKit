CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic

encrypt: main.o md5.o sha1.o sha256.o sha224.o
	$(CC) $(CFLAGS) -o hash main.o md5.o sha1.o sha256.o sha224.o

main.o: main.c md5.h sha1.h sha256.h sha224.h
	$(CC) $(CFLAGS) -c main.c

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) -c md5.c

sha1.o: sha1.c sha1.h
	$(CC) $(CFLAGS) -c sha1.c

sha256.o: sha256.c sha256.h
	$(CC) $(CFLAGS) -c sha256.c

sha224.o: sha224.c sha224.h
	$(CC) $(CFLAGS) -c sha224.c

.PHONY: all
all: hash

clean:
	rm -f hash *.o

