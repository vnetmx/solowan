/*
 * 01dedup.c
 *
 *  Created on: Nov 14, 2013
 *      Author: root
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <linux/types.h>
#include <linux/types.h>
#include "deduplication.h"
#include "01dedup.h"
#include "hash.h"
#include "as.h"


#define LOG_DEDUP 0

int create_hashmap(hashtable *as){
	return as_crear(as, NREG, CHUNK);
}

/*
 * Check functions: it checks the presence of a chunk in the
 * hash table pointed by *as.
 *
 * It returns:	1 if the chunk exists
 * 				0 if not
 * */
int check(hashtable *as, uint32_t hash){
	char tmp[CHUNK];
	return as_leer(as, NORMALIZE(hash), &tmp);
}

/*
 * Deduplicate function: it writes the chunk in the hash table
 * using the hash parameter as a key.
 *
 * It returns:	1 if it successes
 * 				0 if not
 *
 * If the chunk exists, the content is put in the retrieved_chunk buffer
 *
 * */
int put_block(hashtable *as, __u8 *buffer, uint32_t hash){
	int i;
	// Insert buffer in the hash table using the normalized "hash" variable as key
	// We normalize the key according o the table size
	i = as_escribir(as, NORMALIZE(hash), buffer);
	if(i){
//		printf("Ok, everything is gonna be alright! \n");
		return 1;
	}else{
		printf("Error inserting in the table\n");
		return 0;
	}
}

/*
 * Regenerate function: it checks the presence of a chunk in the
 * hash table pointed by *as and returns the content.
 *
 * It returns:	1 if the chunk exists
 * 				0 if not
 *
 * If the chunk exists, the content is put in the retrieved_chunk buffer
 *
 * */
int get_block(uint32_t hash, hashtable *as, __u8 *retrieved_chunk){
//	int i;
//	printf("\nHash:%u\n",hash);
//	printf("Hashed retrieved from message:%u\n", hash);
//	printf("Normalized value of hash:%u\n", NORMALIZE(hash));
	// Look for the table entry
	return as_leer(as, NORMALIZE(hash), retrieved_chunk);
//	if(i){ // Find!
//		printf("Deduplicated value: \n");
		// Write to the stdout
//		fwrite(retrieved_chunk, 1, CHUNK, stdout);
		// Write the deduplicated chunk to the output file
//		fwrite(retrieved_chunk,1,CHUNK,output_file);
//		return 1;
		//		printf("%s\n",buffer);
//	}else{ // Nothing!
//		printf("Not found \n");
//		return 0;
//	}
}

int check_collision(hashtable *as, __u8 *block_ptr, uint32_t hash){
	int i;
	char ptr[CHUNK];

	i =as_leer(as, NORMALIZE(hash), &ptr);
	if (i){
		i = memcmp (ptr, block_ptr, CHUNK);
		if(i != 0){
//			printf("\n%d\n",i);
//			printf("\nCollision!!!!\n");
			return 0;
		}

//		fwrite(ptr,1, CHUNK, stdout);

	}
	return 1;
}

int remove_hashmap(hashtable as){
	return as_cerrar(as);
}
