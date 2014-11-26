/*
 * solowan_basic.h
 *
 *  Created on: Jan 31, 2014
 *      Author: Mattia Peirano
 */

#ifndef SOLOWAN_BASIC_H_
#define SOLOWAN_BASIC_H_

int optimize(__u8 *in_packet, __u16 in_packet_size, __u8 *out_packet, __u16 *out_packet_size);
int deoptimize(__u8 *input_packet_ptr, __u16 input_packet_size, __u8 *regenerated_packet, __u16 *output_packet_size);
int cache(__u8 *packet_ptr, __u16 packet_size);

#endif /* SOLOWAN_BASIC_H_ */
