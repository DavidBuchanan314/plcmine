all: mine

mine: mine.c
	gcc mine.c -o mine -O3 -Wall -Wextra -Wpedantic -Wno-deprecated-declarations -lgmp -lcrypto

mine_nogmp: mine_nogmp.c
	gcc mine_nogmp.c -o mine_nogmp -O3 -Wall -Wextra -Wpedantic -Wno-deprecated-declarations -lcrypto
