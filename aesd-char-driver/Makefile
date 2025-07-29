CC ?= gcc
CFLAGS ?=-g -Wall -Werror

all:
	${CC} ${CFLAGS} ${INCLUDES} ${OBJS} -o aesd-circular-buffer ${LDFLAGS} aesd-circular-buffer.c

clean:
	rm -f *.o aesd-circular-buffer *.elf *.map
