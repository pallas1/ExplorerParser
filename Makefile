CC=gcc
CFLAGS=-I. -O2 -s -Wall -fexceptions -std=c++11
LDFLAGS=-lgmp -lcryptopp -lstdc++
DEPS = utils.h base58.h
OBJ = main.o hash/haval.o hash/keccak.o hash/ripemd.o hash/sha2big.o hash/sha2.o hash/tiger.o hash/whirlpool.o

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

parser: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f hash/*.o *.o parser
