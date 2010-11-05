CC=gcc
CFLAGS=-lpcap -DMONGO_HAVE_STDINT -I./mongo-c-driver/src/ 

-Isrc --std=c99 tutorial.c 
pcapreader: pcapreader.o
	$(CC) $(CFLAGS) mongo-c-driver/src/*.c -o pcapreader pcapreader.o
pcapreader.o: pcapreader.c
	$(CC) $(CFLAGS) -c pcapreader.c

clean:
	rm -rf *.o pcapreader
  
