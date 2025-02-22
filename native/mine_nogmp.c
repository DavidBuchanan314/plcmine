#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <locale.h>

#include "util.h"
#include "bigint.h"

uint8_t (*precomputed)[3][32];
uint8_t (*r_b64)[40]; // first 30 bytes of r, base64-encoded
uint32_t (*k_inv_rDa)[10];
uint32_t (*k_inv)[10];

pthread_mutex_t stdout_mutex;
pthread_mutex_t stats_mutex;

uint64_t total_plcs = 0;
uint64_t total_found = 0;
double start_time = 0.0;

void print_stats(void)
{
	pthread_mutex_lock(&stats_mutex);
	double duration = get_current_timestamp() - start_time;
	double rate = (double)total_plcs/1e6/duration;
	fprintf(
		stderr,
		"  Stats: %'lu PLCs checked in %.3lf seconds (%.1lfM/s avg) Found: %lu\r",
		total_plcs, duration, rate, total_found
	);
	pthread_mutex_unlock(&stats_mutex);
}

struct work_args {
	size_t num_precomputed_rows;
	char *pubkey;
	uint64_t range_start;
	uint64_t range_end;
	char *prefix;
	uint8_t firstbyte;
};

void *do_work(void *ptr)
{
	struct work_args *args = ptr;
	SHA256_CTX sha256;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	uint32_t z[10], s[10];
	
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
		bigint_unpack(z, hash);

		for (size_t j=0; j<args->num_precomputed_rows; j++) {
			// s = ((z * k_inv[j]) + k_inv_rDa[j]), plus low-s
			mod_fma(s, z, k_inv[j], k_inv_rDa[j]);

			// TODO: base64 most of the first half of the sig in the outer loop
			uint8_t raw_sig[64];
			memcpy(&raw_sig[30], &precomputed[j][0][30], 2); // we only need the tail end of r, we precomputed the rest
			bigint_pack(&raw_sig[32], s);
			memcpy(&signed_op[7], r_b64[j], 40);
			bytes_to_b64_string_nopad(&signed_op[7+40], &raw_sig[30], 34);
			//printf("%s\n", signed_op);

			SHA256_Init(&sha256);
			SHA256_Update(&sha256, signed_op, sizeof(signed_op)-1);
			SHA256_Final(hash, &sha256);

			if (hash[0] == args->firstbyte) {
				unsigned char did[24+1];
				bytes_to_b32_multibase(did, hash, 5); // generates 8 bytes of base32
				if (strncmp((char*)did, args->prefix, prefixlen) == 0) {
					// defer the full b32 until now because it's kinda slow
					bytes_to_b32_multibase(did, hash, 15);
					did[24] = 0;

					pthread_mutex_lock(&stats_mutex);
					total_found++;
					pthread_mutex_unlock(&stats_mutex);


					pthread_mutex_lock(&stdout_mutex);

					printf("%s %s 0x", did, handle);
					for (int k=0; k<32; k++) {
						printf("%02x", precomputed[j][2][k]); // k_inv
					}
					printf("\n");
					fflush(stdout);
					print_stats(); // redraw stats line

					pthread_mutex_unlock(&stdout_mutex);
				}
			}
		}
		pthread_mutex_lock(&stats_mutex);
		total_plcs += args->num_precomputed_rows;
		pthread_mutex_unlock(&stats_mutex);
	}
	return NULL;
}

void *stats_loop(void *ptr)
{
	(void)(ptr); // unused

	while (1)
	{
		sleep(1);
		pthread_mutex_lock(&stdout_mutex);
		print_stats();
		pthread_mutex_unlock(&stdout_mutex);
	}
}

int main(int argc, char *argv[])
{
	if (argc != 5) {
		printf("USAGE: %s num_threads precomputed.bin did:key:publickey prefix\n", argv[0]);
		return -1;
	}

	int num_threads = atoi(argv[1]);
	char *precomputed_path = argv[2];
	char *did_pubkey = argv[3];
	char *prefix_str = argv[4];

	if (strlen(did_pubkey) != 57) {
		printf("invalid pubkey length (you need the did:key: prefix)\n");
		return -1;
	}
	if (strlen(prefix_str) < 2) {
		printf("prefix should be at least 2 chars long...\n");
		return -1;
	}
	if (strlen(prefix_str) > 8) {
		printf("prefixes longer than 8 chars are not currently supported. Use grep to filter the output?\n");
		return -1;
	}

	/* load the precomputed data */
	FILE *f = fopen(precomputed_path, "rb");
	assert(f != NULL);
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	rewind(f);
	precomputed = malloc(fsize);
	size_t num_precomputed_rows = fsize / sizeof(precomputed[0]);
	assert(precomputed != NULL);
	assert(fread(precomputed, fsize, 1, f) == 1);
	fclose(f);

	r_b64 = calloc(num_precomputed_rows, sizeof(*r_b64));
	k_inv_rDa = calloc(num_precomputed_rows, sizeof(*k_inv_rDa));
	k_inv = calloc(num_precomputed_rows, sizeof(*k_inv));
	for (size_t i=0; i<num_precomputed_rows; i++) {
		bytes_to_b64_string_nopad(r_b64[i], precomputed[i][0], 30);
		bigint_unpack(k_inv_rDa[i], precomputed[i][1]);
		bigint_unpack(k_inv[i], precomputed[i][2]);
	}

	/* figure out the first byte that the prefix corresponds to */
	uint8_t firstbyte = \
		((strchr((char*)B32_CHARSET, prefix_str[0])-(char*)B32_CHARSET) << 3) |
		((strchr((char*)B32_CHARSET, prefix_str[1])-(char*)B32_CHARSET) >> 2);

	pthread_t *threads = calloc(num_threads, sizeof(*threads));
	struct work_args *argses = calloc(num_threads, sizeof(*argses));

	fprintf(stderr, "imported %lu rows, running on %d threads\n", num_precomputed_rows, num_threads);

	setlocale(LC_NUMERIC, ""); // let the stats print with decimal separators

	start_time = get_current_timestamp();

#ifdef BENCHMARK
	uint64_t total_iters = 1000;
#else
	pthread_t stats_thread;
	pthread_create(&stats_thread, NULL, *stats_loop, NULL);

	uint64_t total_iters = 0x1000000000L; // run ~forever (hit ctrl+c when you're done)
#endif
	for (int i=0; i<num_threads; i++) {
		argses[i].num_precomputed_rows = num_precomputed_rows;
		argses[i].pubkey = argv[3];
		argses[i].range_start = total_iters*i/num_threads;
		argses[i].range_end = total_iters*(i+1)/num_threads;
		argses[i].prefix = prefix_str;
		argses[i].firstbyte = firstbyte;
		pthread_create(&threads[i], NULL, *do_work, &argses[i]);
	}

	for (int i=0; i<num_threads; i++) {
		pthread_join(threads[i], NULL);
	}
#ifndef BENCHMARK
	pthread_join(stats_thread, NULL);
#endif

	print_stats();
	fprintf(stderr, "\n");
}
