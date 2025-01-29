#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <pthread.h>

#include "util.h"

uint8_t (*precomputed)[3][32];
mpz_t *k_inv_rDa;
mpz_t *k_inv;

pthread_mutex_t stdout_mutex;

struct work_args {
	size_t num_precomputed_rows;
	char *pubkey;
	uint64_t range_start;
	uint64_t range_end;
	char *prefix;
};

void *do_work(void *ptr)
{
	struct work_args *args = ptr;
	SHA256_CTX sha256;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	mpz_t z, s, n, half_n;
	mpz_init(z);
	mpz_init(s);
	mpz_init(n);
	mpz_init(half_n);
	mpz_set_str(n, "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0);
	mpz_set_str(half_n, "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", 0);
	unsigned char signed_op[] = "\xa7""csigxVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdprev\xf6""dtypemplc_operationhservices\xa0""kalsoKnownAs\x81""kat://000004lrotationKeys\x81""x9did:key:zQ3shnemVPxSsadcoTuFmMW7YoETBAmM9UZoxn1vnpjD4yruesverificationMethods\xa0";
	// ^ sig at offset 7, handle at offset 147, pubkey at offset 169

	memcpy(&signed_op[169], args->pubkey, strlen(args->pubkey));

	size_t prefixlen = strlen(args->prefix);

	//printf("%lu %lu\n", args->range_start, args->range_end);
	for (uint64_t i=args->range_start; i<args->range_end; i++) {
		char presigned[155+1];
		char handle[6+1];
		handle[6] = 0;
		for (int j=0; j<6; j++) {
			handle[5-j] = B64_CHARSET[(i>>(j*6))&0x3f];
		}
		snprintf(presigned, sizeof(presigned), "\xa6""dprev\xf6""dtypemplc_operationhservices\xa0""kalsoKnownAs\x81""kat://%slrotationKeys\x81""x9%ssverificationMethods\xa0", handle, args->pubkey);
		memcpy(&signed_op[147], handle, 6);
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, presigned, sizeof(presigned)-1);
		SHA256_Final(hash, &sha256);
		mpz_import(z, 32, 1, 1, 1, 0, hash);

		for (size_t j=0; j<args->num_precomputed_rows; j++) {
			// s = ((z * k_inv[j]) + k_inv_rDa[j])
			mpz_mul(s, z, k_inv[j]);
			mpz_add(s, s, k_inv_rDa[j]);
			mpz_mod(s, s, n); // there's almost certainly a faster way of doing the modmul here

			// low-s
			if (mpz_cmp(s, half_n) > 0) {
				mpz_sub(s, n, s);
			}

			uint8_t raw_sig[64];
			memcpy(raw_sig, precomputed[j][0], 32);
			memset(&raw_sig[32], 0, 32);
			uint8_t s_tmp[32];
			size_t count;
			mpz_export(s_tmp, &count, 1, 1, 1, 0, s);
			memcpy(&raw_sig[64-count], s_tmp, count);

			bytes_to_b64_string_nopad(&signed_op[7], raw_sig, 64);
			//printf("%s\n", signed_op);

			SHA256_Init(&sha256);
			SHA256_Update(&sha256, signed_op, sizeof(signed_op)-1);
			SHA256_Final(hash, &sha256);

			// it'd be cheaper to comare the hash bytes rather than b32, but I'm lazy
			unsigned char did[24+1];
			bytes_to_b32_multibase(did, hash, 5); // generates 8 bytes of base32
			if (strncmp((char*)did, args->prefix, prefixlen) == 0) {
				// defer the full b32 until now because it's kinda slow
				bytes_to_b32_multibase(did, hash, 15);
				did[24] = 0;
				pthread_mutex_lock(&stdout_mutex);
				gmp_printf("%s %s %#Zx\n", did, handle, k_inv[j]);
				pthread_mutex_unlock(&stdout_mutex);
			}
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	if (argc != 5) {
		printf("USAGE: %s num_threads precomputed.bin did:key:publickey prefix\n", argv[0]);
		return -1;
	}

	/* load the precomputed data */
	FILE *f = fopen(argv[2], "rb");
	assert(f != NULL);
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	rewind(f);
	precomputed = malloc(fsize);
	size_t num_precomputed_rows = fsize / sizeof(precomputed[0]);
	assert(precomputed != NULL);
	assert(fread(precomputed, fsize, 1, f) == 1);
	fclose(f);

	k_inv_rDa = calloc(num_precomputed_rows, sizeof(*k_inv_rDa));
	k_inv = calloc(num_precomputed_rows, sizeof(*k_inv));
	for (size_t i=0; i<num_precomputed_rows; i++) {
		mpz_init(k_inv_rDa[i]);
		mpz_init(k_inv[i]);
		mpz_import(k_inv_rDa[i], 32, 1, 1, 1, 0, precomputed[i][1]);
		mpz_import(k_inv[i], 32, 1, 1, 1, 0, precomputed[i][2]);
	}

	int num_threads = atoi(argv[1]);
	pthread_t *threads = calloc(num_threads, sizeof(*threads));
	struct work_args *argses = calloc(num_threads, sizeof(*argses));

	fprintf(stderr, "imported %lu rows, running on %d threads\n", num_precomputed_rows, num_threads);

	uint64_t total_iters = 0x1000000000L; // run ~forever (hit ctrl+c when you're done)
	for (int i=0; i<num_threads; i++) {
		argses[i].num_precomputed_rows = num_precomputed_rows;
		argses[i].pubkey = argv[3];
		argses[i].range_start = total_iters*i/num_threads;
		argses[i].range_end = total_iters*(i+1)/num_threads;
		argses[i].prefix = argv[4];
		pthread_create(&threads[i], NULL, *do_work, &argses[i]);
	}

	for (int i=0; i<num_threads; i++) {
		pthread_join(threads[i], NULL);
	}
}
