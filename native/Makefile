all: mine

override CFLAGS += -O3 -Wall -Wextra -Wpedantic -Wno-deprecated-declarations

# make mine_nogmp CFLAGS=-DBENCHMARK

mine: mine.c
	gcc mine.c -o mine $(CFLAGS) -lgmp -lcrypto

mine_nogmp: mine_nogmp.c
	gcc mine_nogmp.c -o mine_nogmp $(CFLAGS) -lcrypto
