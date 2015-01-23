CC=gcc
CFLAGS= -Wall  -g

TARGET=ts_packet
OBJS=ts_packet.o

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) -o $@ $^
%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $^
	
clean:
	rm *.o
