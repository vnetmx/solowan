/*

  packet.c

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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "packet.h"

struct packet *newpacket(void)
{
    struct packet *thispacket = NULL;

    thispacket = calloc(1,sizeof(struct packet)); // Allocate space for a new packet.
    thispacket->head = NULL;
    thispacket->next = NULL;
    thispacket->prev = NULL;

    return thispacket;
}

int save_packet(struct packet *thispacket,struct nfq_q_handle *hq, u_int32_t id, int ret, __u8 *originalpacket, struct session *thissession)
{
	thispacket->hq = hq; // Save the queue handle.
	thispacket->id = id; // Save this packets id.
	memmove(thispacket->data, originalpacket, ret); // Save the packet.
	
	return 0;
}
