CC ?= gcc
CFLAGS ?=-g -Wall -Werror

all:
	${CC} ${CFLAGS} ${INCLUDES} ${OBJS} -o aesdsocket ${LDFLAGS} aesdsocket.c

clean:
	rm -f *.o aesdsocket *.elf *.map
