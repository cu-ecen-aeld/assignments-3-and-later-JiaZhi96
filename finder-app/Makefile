compiler?=$(CROSS_COMPILE)gcc

all:
	${CC} ${CFLAGS} ${INCLUDES} ${OBJS} -o writer ${LDFLAGS} writer.c

clean:
	rm -f *.o writer *.elf *.map
