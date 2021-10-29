CC=gcc
CFLAGS= -Wall -Wextra -Wpedantic -Werror

all: example

mac_log.o: mac_log.c mac_log.h

example: example.c mac_log.o

.PHONY:
clean:
	rm -f example *.o
