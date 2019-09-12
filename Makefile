CC = gcc
CFLAGS += -g 
#CFLAGS += -O2 -Wall -W -Werror
LDFLAGS += -libverbs -lrdmacm -lmlx5
TARGETS = dcping

all:
	$(CC) $(CFLAGS) -o $(TARGETS) dcping.c $(LDFLAGS)

clean:
	rm -f $(TARGETS)
