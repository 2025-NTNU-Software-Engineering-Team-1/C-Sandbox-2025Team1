# fake target
.PHONY: all clean
# variables
CC = gcc
CFLAGS = -lpthread -lseccomp -Wall

all: sandbox sandbox_interactive

sandbox: sandbox.c
	$(CC) -o sandbox sandbox.c $(CFLAGS)

sandbox_interactive: sandbox_interactive.c
	$(CC) -o sandbox_interactive sandbox_interactive.c $(CFLAGS)

test: sandbox
	./sandbox 0 1 /dev/null /dev/null /dev/null 1000  1024000 1 1024000 10 0 result

clean:
	rm -f sandbox sandbox_interactive
	rm -f stdin stdout stderr result main
