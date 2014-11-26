/*
 * hash.h
 *
 *  Created on: Nov 18, 2013
 *      Author: root
 */

#ifndef HASH_H_
#define HASH_H_
#include <stdint.h>
#include <linux/types.h>

uint32_t SuperFastHash (const __u8 * data, int len);

#endif /* HASH_H_ */
