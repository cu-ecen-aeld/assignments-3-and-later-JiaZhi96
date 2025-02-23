compiler?=$(CROSS_COMPILE)gcc

all:
	$(compiler) -g -Wall -c -o writer.o writer.c
	$(compiler) -g -Wall -I/ writer.o -o writer

clean:
	rm -f *.o writer *.elf *.map
