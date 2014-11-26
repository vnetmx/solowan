/*

  fetcher.h

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

#ifndef FETCHER_H_
#define FETCHER_H_
#define _GNU_SOURCE

#include <pthread.h>

#include <libnetfilter_queue/libnetfilter_queue.h> // for access to Netfilter Queue
#include "counters.h"

struct fetchercounters {
	/*
	 * number of packets processed.
	 * used for pps calculation. can roll.
	 * should increment at end of main loop after each packet is finished processing.
	 */
	__u32 packets;
	__u32 packetsprevious;
	__u32 pps; // Where the calculated pps are stored.

	/*
	 * number of bytes entering process.
	 * used for bps calculation. can roll.
	 * should increment as beginning of main loop after packet is received from queue.
	 */
	__u32 bytesin;
	__u32 bytesinprevious;
	__u32 bpsin; // Where the calculated bps are stored.

	/*
	 * Stores when the counters were last updated.
	 */
	struct timeval updated;

	/*
	 * When something reads/writes to this counter it should use the lock.
	 */
	pthread_mutex_t lock;
};

struct fetcher {
	pthread_t t_fetcher;
	struct fetchercounters metrics;
	int state; // Marks this thread as active. 1=running, 0=stopping, -1=stopped.
	pthread_mutex_t lock; // Lock for the fetcher when changing state.
};

int fetcher_callback(struct nfq_q_handle *hq, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data);

void *fetcher_function(void *dummyPtr);
void fetcher_graceful_exit();
void create_fetcher();
void rejoin_fetcher();
int cli_show_fetcher(int client_fd, char **parameters, int numparameters);
void counter_updatefetchermetrics(t_counterdata data);

#endif /*FETCHER_H_*/
