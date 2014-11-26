/*

  session.h

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

#ifndef SESSION_H_
#define SESSION_H_

#include <sys/types.h>

#include <linux/types.h>

/* Structure used for the head of a session list. */
struct session_head {
	struct session *next; /* Points to the first session of the list. */
	struct session *prev; /* Points to the last session of the list. */
	u_int32_t qlen; // Total number of sessions in the list.
	pthread_mutex_t lock; // Lock for this session bucket.
};

/* Structure used to store TCP session info. */
struct session {
	struct session_head *head; // Points to the head of this list.
	struct session *next; // Points to the next session in the list.
	struct session *prev; // Points to the previous session in the list.
	__u32 *client; // Points to the client IP Address.
	__u32 *server; // Points to the server IP Address.
	__u32 largerIP; // Stores the larger IP address.
	__u16 largerIPPort; // Stores the larger IP port #.
	__u32 largerIPStartSEQ; // Stores the starting SEQ number.
	__u32 largerIPseq; // Stores the TCP SEQ from the largerIP.
	__u32 largerIPAccelerator; // Stores the AcceleratorIP of the largerIP.
	__u32 smallerIP; // Stores the smaller IP address.
	__u16 smallerIPPort; // Stores the smaller IP port #.
	__u32 smallerIPStartSEQ; // Stores the starting SEQ number.
	__u32 smallerIPseq; // Stores the TCP SEQ from the smallerIP.
	__u32 smallerIPAccelerator; // Stores the AcceleratorIP of the smallerIP.
	__u64 lastactive; // Stores the time this session was last active.
	__u8 deadcounter; // Stores how many counts the session has been idle.
	__u8 state; // Stores the TCP session state.
	__u8 queue; // What worker queue the packets for this session go to.
};


#endif /*SESSION_H_*/
