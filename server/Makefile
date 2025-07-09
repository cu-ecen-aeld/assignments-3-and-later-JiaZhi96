# $(compiler) -g -Wall -c -o writer.o writer.c
# $(compiler) -g -Wall -I/ writer.o -o writer
CC ?= gcc
CFLAGS ?=-g -Wall -Werror
all:
	${CC} ${CFLAGS} ${INCLUDES} ${OBJS} -o aesdsocket ${LDFLAGS} aesdsocket.c

clean:
	rm -f *.o aesdsocket *.elf *.map
