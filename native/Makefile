all: mine

override CFLAGS += -march=native -mtune=native -O3 -flto -Wall -Wextra -Wpedantic -Wno-deprecated-declarations -Wno-format

# make mine_nogmp CFLAGS=-DBENCHMARK

mine: mine.c util.h
	$(CC) mine.c -o mine $(CFLAGS) -lgmp -lcrypto

mine_nogmp: mine_nogmp.c util.h bigint.h
	$(CC) mine_nogmp.c -o mine_nogmp $(CFLAGS) -lcrypto
