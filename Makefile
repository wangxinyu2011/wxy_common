

CROSS_COMPILE=
CC=$(CROSS_COMPILE)gcc

CFLAGS=-Wall

EXEC=test
OBJS=main.o wxy_common.o

all:clean $(EXEC)
	@echo "compile complete!"

$(EXEC):$(OBJS)
	$(CC) -o $@ $^

clean:
	rm -f $(EXEC) $(OBJS)
