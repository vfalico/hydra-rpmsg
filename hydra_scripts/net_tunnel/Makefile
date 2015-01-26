all: tunnel

tunnel: tunnel.c
	$(CC) $(CC_FLAGS) -static -o $@ tunnel.c -lpthread

.PHONY: clean
clean:
	rm -f *.o tunnel

