/*
 * 01dedup.h
 *
 *  Created on: Nov 14, 2013
 *      Author: root
 */

#ifndef DEDUP_H_
#define DEDUP_H_

#include <stdint.h>
#include "as.h"
#include <linux/types.h>

#define NREG 10000000
#define NORMALIZE(hash) hash%NREG

#define LOG_DEDUP 0

typedef as hashtable;

int create_hashmap(hashtable *as);

/*
 * Check functions: it checks the presence of a chunk in the
 * hash table pointed by *as.
 *
 * It returns:	1 if the chunk exists
 * 				0 if not
 * */
int check(hashtable *as, uint32_t hash);

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
int put_block(hashtable *as, __u8 *buffer, uint32_t hash);

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
int get_block(uint32_t hash, hashtable *as, __u8 *retrieved_chunk);

int check_collision(hashtable *as, __u8 *block_ptr, uint32_t hash);

int remove_hashmap(hashtable as);

#endif /* 01DEDUP_H_ */
