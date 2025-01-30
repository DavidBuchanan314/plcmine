all: mine

override CFLAGS += -O3 -Wall -Wextra -Wpedantic -Wno-deprecated-declarations

# make mine_nogmp CFLAGS=-DBENCHMARK

mine: mine.c util.h
	gcc mine.c -o mine $(CFLAGS) -lgmp -lcrypto

mine_nogmp: mine_nogmp.c util.h bigint.h
	gcc mine_nogmp.c -o mine_nogmp $(CFLAGS) -lcrypto
