#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bigint.h"
#include "sha256.h"
#include "util.h"

int main()
{
	uint32_t state[8];
	uint32_t buf0[0x10] = {
		0xa6647072, 0x6576f664, 0x74797065, 0x6d706c63,
		0x5f6f7065, 0x72617469, 0x6f6e6873, 0x65727669,
		0x636573a0, 0x6b616c73, 0x6f4b6e6f, 0x776e4173,
		0x81781c41, 0x41414141, 0x41414141, 0x41414141
	};
	uint32_t buf1[0x10] = {
		0x41414141, 0x41414141, 0x41414141, 0x4141416c,
		0x726f7461, 0x74696f6e, 0x4b657973, 0x81783964,
		0x69643a6b, 0x65793a7a, 0x51337368, 0x585a7079,
		0x6b333144, 0x6b575852, 0x594d454d, 0x4b32314a
	};
	uint32_t buf2[0x10] = {
		0x327a6876, 0x624b7135, 0x486f5763, 0x36657663,
		0x34503638, 0x70686a77, 0x73766572, 0x69666963,
		0x6174696f, 0x6e4d6574, 0x686f6473, 0xa0800000,
		0x00000000, 0x00000000, 0x00000000, 0x00000568
	};

	// Todo: populate tweak and pubkey into buf0-2

	sha256_init(state)
	sha256_block(state, buf0);
	sha256_block(state, buf1);
	sha256_block(state, buf2);

	for (int i=0; i<8; i++) {
		printf("%08x", state[i]);
	}
	printf("\n");

	uint32_t x[10];
	bigint_unpack_le32(x, (uint8_t*)state);

	uint32_t s[10];
	mod_fma(s, x, x, x);
	
	uint8_t raw_sig[64];
	memcpy(&raw_sig[30], "XX", 2); // we only need the tail end of r, we precomputed the rest
	bigint_pack(&raw_sig[32], s);

	uint8_t sig64[46+1];
	bytes_to_b64_string_nopad(sig64, &raw_sig[30], 34);

	sig64[46] = 0;
	printf("%s\n", sig64);
}
