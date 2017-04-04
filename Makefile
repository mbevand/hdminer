# Update SDK_PATH to point to the AMD APP SDK (previously ATI Stream SDK)
SDK_PATH = /usr/local/ati-stream

CPPFLAGS = -I$(SDK_PATH)/include/CAL -I$(SDK_PATH)/include -Ijansson
CFLAGS = -pthread -O1 -std=c99 -pedantic -Wextra -Wall \
	 -Wno-overlength-strings
LDFLAGS = -laticalcl -laticalrt -lcurl -lm
KERNELS = \
	  kernel-sha256.h

all: hdminer

hdminer: hdminer.o cal-utils.o miner-utils.o libjansson.a

hdminer.o: hdminer.c $(KERNELS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ hdminer.c

$(KERNELS) : kernel-sha256.pl
	./kernel-sha256.pl

clean:
	rm -f *.o hdminer kernel-sha256*.h jansson/*.o libjansson.a

libjansson.a:
	sh -c 'cd jansson && $(CC) $(CFLAGS) -I. -c *.c'
	$(AR) cru $@ jansson/*.o
	ranlib $@
