CC = gcc
CFLAGS += -g 
#CFLAGS += -O2 -Wall -W -Werror
LDFLAGS = -libverbs -lrdmacm -lmlx5
TARGETS = pingmesh

all:
	$(CC) $(CFLAGS) -o $(TARGETS) pingmesh.c $(LDFLAGS)

clean:
	rm -f $(TARGETS)
