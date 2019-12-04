CC=gcc
CFLAGS=-I. -O2 -s -Wall -m64 -fexceptions -std=c++11

#Normal dynamic build:
#LDFLAGS=-lgmp -lcryptopp -lstdc++
#Static build:
LDFLAGS=../cryptopp/libcryptopp.a -l:libgmp.a -lstdc++ -lm

DEPS = utils.h base58.h
OBJ = main.o hash/haval.o hash/keccak.o hash/ripemd.o hash/sha2big.o hash/sha2.o hash/tiger.o hash/whirlpool.o

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

parser: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f hash/*.o *.o parser
