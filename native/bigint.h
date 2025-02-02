
#include <stdint.h>

/*

compute:

res = ((a * b) + c) mod n
if res > n//2:
	res = n - res

(where n comes from secp256k1)

integers are represented as 10x 26-bit limbs.

n.b. this is an insecure implementation, the result is *probably* fully reduced
but it is not guaranteed.
there are no data-dependent branches but I haven't thought about constant-time-ness

perf note: we want to hint at the compiler to generate 32x32->64 widening multiplies

there's scope for unrolling and/or combining adjacent loops but I'm kinda banking
on the compiler being smart.

*/
static const uint32_t N[10] = {3555649, 9937716, 33799165, 60472610, 45788892, 67108863, 67108863, 67108863, 67108863, 4194303};
static const uint32_t C[5] = {63553215, 57171147, 33309698, 6636253, 21319971}; // (2^256) - n

static void mod_fma(uint32_t res[10], const uint32_t a[10], const uint32_t b[10], const uint32_t c[10])
{
	uint64_t tmp[20] = {0};
	uint32_t tmp_hi[10] = {0};

	// textbook mul
	for (int i=0; i<10; i++) {
		for (int j=0; j<10; j++) {
			tmp[i+j] += (uint64_t)a[i] * (uint64_t)b[j];
		}
	}

	// partial carry + extract high-half
	tmp[9+1] += tmp[9]>>26;
	tmp[9] &= (1<<26)-1;
	for (int i=10; i<19; i++) {
		tmp[i+1] += tmp[i]>>26;
		tmp_hi[i-10] = (tmp[i] & ((1<<26)-1))<<4;
		tmp[i] = 0;
	}
	tmp_hi[19-10] = tmp[19]<<4;
	// reduction
	for (int i=0; i<10; i++) {
		for (int j=0; j<5; j++) {
			tmp[i+j] += (uint64_t)tmp_hi[i] * (uint64_t)C[j];
		}
	}
	
	/*printf("first reduction\n[");
	for (int i=0; i<20; i++) {
		printf("%llu, ", tmp1[i]);
	}
	printf("]\n");*/


	// partial carry + extract high-half
	tmp[9+1] += tmp[9]>>26;
	tmp[9] &= (1<<26)-1;
	for (int i=10; i<14; i++) {
		tmp[i+1] += tmp[i]>>26;
		tmp_hi[i-10] = (tmp[i] & ((1<<26)-1))<<4;
		tmp[i] = 0;
	}
	tmp_hi[14-10] = tmp[14]<<4;
	// reduction
	for (int i=0; i<5; i++) {
		for (int j=0; j<5; j++) {
			tmp[i+j] += (uint64_t)tmp_hi[i] * (uint64_t)C[j];
		}
	}

	/*printf("chi\n[");
	for (int i=0; i<5; i++) {
		printf("%llu, ", tmp_hi[i]);
	}
	printf("]\n");*/


	/*printf("after second reduction\n[");
	for (int i=0; i<20; i++) {
		printf("%llu, ", tmp1[i]);
	}
	printf("]\n");*/

	// sneaky addition
	for (int i=0; i<10; i++) {
		tmp[i] += c[i];
	}

	// partial carry
	for (int i=0; i<10; i++) {
		tmp[i+1] += tmp[i]>>26;
		tmp[i] &= (1<<26)-1;
	}

	/*printf("after third carry\n[");
	for (int i=0; i<20; i++) {
		printf("%llu, ", tmp1[i]);
	}
	printf("]\n");*/

	// final reduction
	tmp_hi[0] = (tmp[9]>>22) + (tmp[10]<<4);
	//tmp[10] = 0;
	//tmp[9] &= (1<<22)-1;
	for (int i=0; i<1; i++) {
		for (int j=0; j<5; j++) {
			tmp[i+j] += (uint64_t)tmp_hi[i] * (uint64_t)C[j];
		}
	}

	// final carry
	for (int i=0; i<10; i++) {
		tmp[i+1] += tmp[i]>>26;
		tmp[i] &= (1<<26)-1;
	}

	/*printf("final\n[");
	for (int i=0; i<20; i++) {
		printf("%llu, ", tmp1[i]);
	}
	printf("]\n");*/

	// result
	for (int i=0; i<10; i++) {
		res[i] = tmp[i];
	}

	// low-s:
	// note: since n//2 starts with a bunch of ones, we can just check the MSB to determine whether s is high or low
	// (this is ultimately a heuristic but it's good enough for us)
	if (res[9] & (1<<21)) {
		// subtraction
		for (int i=0; i<10; i++) {
			res[i] = N[i] - res[i];
		}
		// underflow carry
		for (int i=0; i<9; i++) {
			res[i+1] -= res[i]>>31;
			res[i] &= (1<<26)-1;
		}
	}
}

// this doesn't need to go too fast, it's not in the inner loop
// note, buf is big-endian (most significant first), res limbs are 26-bit (least significant first)
static void bigint_unpack(uint32_t res[10], const uint8_t buf[32])
{
	// thanks deepseek
	res[0] = ((uint32_t)buf[31] <<  0) | ((uint32_t)buf[30] <<  8) |
	         ((uint32_t)buf[29] << 16) | ((uint32_t)(buf[28] & 0x03) << 24);
	res[0] &= 0x03FFFFFF; // 26-bit mask

	res[1] = ((uint32_t)(buf[28] >> 2) <<  0) | ((uint32_t)buf[27] <<  6) |
	         ((uint32_t)buf[26] << 14) | ((uint32_t)(buf[25] & 0x0F) << 22);
	res[1] &= 0x03FFFFFF;

	res[2] = ((uint32_t)(buf[25] >> 4) <<  0) | ((uint32_t)buf[24] <<  4) |
	         ((uint32_t)buf[23] << 12) | ((uint32_t)(buf[22] & 0x3F) << 20);
	res[2] &= 0x03FFFFFF;

	res[3] = ((uint32_t)(buf[22] >> 6) <<  0) | ((uint32_t)buf[21] <<  2) |
	         ((uint32_t)buf[20] << 10) | ((uint32_t)buf[19] << 18);
	res[3] &= 0x03FFFFFF;

	res[4] = ((uint32_t)buf[18] <<  0) | ((uint32_t)buf[17] <<  8) |
	         ((uint32_t)buf[16] << 16) | ((uint32_t)(buf[15] & 0x03) << 24);
	res[4] &= 0x03FFFFFF;

	res[5] = ((uint32_t)(buf[15] >> 2) <<  0) | ((uint32_t)buf[14] <<  6) |
	         ((uint32_t)buf[13] << 14) | ((uint32_t)(buf[12] & 0x0F) << 22);
	res[5] &= 0x03FFFFFF;

	res[6] = ((uint32_t)(buf[12] >> 4) <<  0) | ((uint32_t)buf[11] <<  4) |
	         ((uint32_t)buf[10] << 12) | ((uint32_t)(buf[9]  & 0x3F) << 20);
	res[6] &= 0x03FFFFFF;

	res[7] = ((uint32_t)(buf[9]  >> 6) <<  0) | ((uint32_t)buf[8]  <<  2) |
	         ((uint32_t)buf[7]  << 10) | ((uint32_t)buf[6]  << 18);
	res[7] &= 0x03FFFFFF;

	res[8] = ((uint32_t)buf[5] <<  0) | ((uint32_t)buf[4] <<  8) |
	         ((uint32_t)buf[3] << 16) | ((uint32_t)(buf[2]  & 0x03) << 24);
	res[8] &= 0x03FFFFFF;

	res[9] = ((uint32_t)(buf[2] >> 2) <<  0) | ((uint32_t)buf[1] <<  6) |
	         ((uint32_t)buf[0] << 14);
	res[9] &= 0x003FFFFF; // 22-bit mask for last limb
}

// as above but each 32-bit word is endian-swapped (as in the output of raw sha256)
static void bigint_unpack_le32(uint32_t res[10], const uint8_t buf[32])
{
	// thanks deepseek
	res[0] = ((uint32_t)buf[28] <<  0) | ((uint32_t)buf[29] <<  8) |
	         ((uint32_t)buf[30] << 16) | ((uint32_t)(buf[31] & 0x03) << 24);
	res[0] &= 0x03FFFFFF; // 26-bit mask

	res[1] = ((uint32_t)(buf[31] >> 2) <<  0) | ((uint32_t)buf[24] <<  6) |
	         ((uint32_t)buf[25] << 14) | ((uint32_t)(buf[26] & 0x0F) << 22);
	res[1] &= 0x03FFFFFF;

	res[2] = ((uint32_t)(buf[26] >> 4) <<  0) | ((uint32_t)buf[27] <<  4) |
	         ((uint32_t)buf[20] << 12) | ((uint32_t)(buf[21] & 0x3F) << 20);
	res[2] &= 0x03FFFFFF;

	res[3] = ((uint32_t)(buf[21] >> 6) <<  0) | ((uint32_t)buf[22] <<  2) |
	         ((uint32_t)buf[23] << 10) | ((uint32_t)buf[16] << 18);
	res[3] &= 0x03FFFFFF;

	res[4] = ((uint32_t)buf[17] <<  0) | ((uint32_t)buf[18] <<  8) |
	         ((uint32_t)buf[19] << 16) | ((uint32_t)(buf[12] & 0x03) << 24);
	res[4] &= 0x03FFFFFF;

	res[5] = ((uint32_t)(buf[12] >> 2) <<  0) | ((uint32_t)buf[13] <<  6) |
	         ((uint32_t)buf[14] << 14) | ((uint32_t)(buf[15] & 0x0F) << 22);
	res[5] &= 0x03FFFFFF;

	res[6] = ((uint32_t)(buf[15] >> 4) <<  0) | ((uint32_t)buf[8] <<  4) |
	         ((uint32_t)buf[9] << 12) | ((uint32_t)(buf[10]  & 0x3F) << 20);
	res[6] &= 0x03FFFFFF;

	res[7] = ((uint32_t)(buf[10]  >> 6) <<  0) | ((uint32_t)buf[11]  <<  2) |
	         ((uint32_t)buf[4]  << 10) | ((uint32_t)buf[5]  << 18);
	res[7] &= 0x03FFFFFF;

	res[8] = ((uint32_t)buf[6] <<  0) | ((uint32_t)buf[7] <<  8) |
	         ((uint32_t)buf[0] << 16) | ((uint32_t)(buf[1]  & 0x03) << 24);
	res[8] &= 0x03FFFFFF;

	res[9] = ((uint32_t)(buf[1] >> 2) <<  0) | ((uint32_t)buf[2] <<  6) |
	         ((uint32_t)buf[3] << 14);
	res[9] &= 0x003FFFFF; // 22-bit mask for last limb
}

// the reverse of the above
static void bigint_pack(uint8_t resbuf[32], const uint32_t bigint[10])
{
	resbuf[31] = (bigint[0] >> 0) & 0xFF;
	resbuf[30] = (bigint[0] >> 8) & 0xFF;
	resbuf[29] = (bigint[0] >> 16) & 0xFF;
	resbuf[28] = (bigint[0] >> 24) & 0x03;

	resbuf[28] |= (bigint[1] & 0x3F) << 2;
	resbuf[27] = (bigint[1] >> 6) & 0xFF;
	resbuf[26] = (bigint[1] >> 14) & 0xFF;
	resbuf[25] = (bigint[1] >> 22) & 0x0F;

	resbuf[25] |= (bigint[2] & 0x0F) << 4;
	resbuf[24] = (bigint[2] >> 4) & 0xFF;
	resbuf[23] = (bigint[2] >> 12) & 0xFF;
	resbuf[22] = (bigint[2] >> 20) & 0x3F;

	resbuf[22] |= (bigint[3] & 0x03) << 6;
	resbuf[21] = (bigint[3] >> 2) & 0xFF;
	resbuf[20] = (bigint[3] >> 10) & 0xFF;
	resbuf[19] = (bigint[3] >> 18) & 0xFF;

	resbuf[18] = (bigint[4] >> 0) & 0xFF;
	resbuf[17] = (bigint[4] >> 8) & 0xFF;
	resbuf[16] = (bigint[4] >> 16) & 0xFF;
	resbuf[15] = (bigint[4] >> 24) & 0x03;

	resbuf[15] |= (bigint[5] & 0x3F) << 2;
	resbuf[14] = (bigint[5] >> 6) & 0xFF;
	resbuf[13] = (bigint[5] >> 14) & 0xFF;
	resbuf[12] = (bigint[5] >> 22) & 0x0F;

	resbuf[12] |= (bigint[6] & 0x0F) << 4;
	resbuf[11] = (bigint[6] >> 4) & 0xFF;
	resbuf[10] = (bigint[6] >> 12) & 0xFF;
	resbuf[9]  = (bigint[6] >> 20) & 0x3F;

	resbuf[9] |= (bigint[7] & 0x03) << 6;
	resbuf[8] = (bigint[7] >> 2) & 0xFF;
	resbuf[7] = (bigint[7] >> 10) & 0xFF;
	resbuf[6] = (bigint[7] >> 18) & 0xFF;

	resbuf[5] = (bigint[8] >> 0) & 0xFF;
	resbuf[4] = (bigint[8] >> 8) & 0xFF;
	resbuf[3] = (bigint[8] >> 16) & 0xFF;
	resbuf[2] = (bigint[8] >> 24) & 0x03;

	resbuf[2] |= (bigint[9] & 0x3F) << 2;
	resbuf[1] = (bigint[9] >> 6) & 0xFF;
	resbuf[0] = (bigint[9] >> 14) & 0xFF;
}
