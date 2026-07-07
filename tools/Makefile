CC ?= gcc
CFLAGS := -Wall -g
LDFLAGS := -lpthread -lrt

all: trigger

trigger: trigger.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@
	@echo "  ./tools/trigger <tcp|udp|mq|mutex|fs|syscall|sched|slab|all>"

clean:
	rm -f trigger
