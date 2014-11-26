/*

  packet.h

  This file is part of OpenNOP-SoloWAN distribution.
  No modifications made from the original file in OpenNOP distribution.

  Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

    OpenNOP is an open source Linux based network accelerator designed 
    to optimise network traffic over point-to-point, partially-meshed and 
    full-meshed IP networks.

  References:

    OpenNOP: http://www.opennop.org

  License:

    OpenNOP is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenNOP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef PACKET_H_
#define PACKET_H_
#define _GNU_SOURCE

#include <stdint.h>
#include <pthread.h>

#include <linux/types.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "session.h"

#define BUFSIZE 2048 // Size of buffer used to store IP packets.

/* Structure used for the head of a packet queue.. */
struct packet_head
{
    struct packet *next; // Points to the first packet of the list.
    struct packet *prev; // Points to the last packet of the list.
    u_int32_t qlen; // Total number of packets in the list.
    pthread_cond_t signal; // Condition signal used to wake-up thread.
    pthread_mutex_t lock; // Lock for this queue.
};

struct packet
{
    struct packet_head *head; // Points to the head of this list.
    struct packet *next; // Points to the next packet.
    struct packet *prev; // Points to the previous packet.
    struct nfq_q_handle *hq; // The Queue Handle to the Netfilter Queue.
    u_int32_t id; // The ID of this packet in the Netfilter Queue.
    unsigned char data[BUFSIZE]; // Stores the actual IP packet.
};

struct packet *newpacket(void);

int save_packet(struct packet *thispacket,struct nfq_q_handle *hq, u_int32_t id, int ret, __u8 *originalpacket, struct session *thissession);

#endif /*PACKET_H_*/
