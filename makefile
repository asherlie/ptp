CC=gcc
CFLAGS= -Wall -Wextra -Wpedantic -Werror -pthread -DREADLINE -lreadline -lpcap -g

#all: example
all: ptp 

persist.o: persist.c persist.h
mq.o: mq.c mq.h
mac_log.o: mac_log.c mac_log.h

example: example.c mac_log.o mq.o
ptp: ptp.c mq.o mac_log.o persist.o

.PHONY:
clean:
	rm -f example *.o
