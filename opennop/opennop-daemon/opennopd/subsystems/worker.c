/*

  worker.c

  This file is part of OpenNOP-SoloWAN distribution.
  It is a modified version of the file originally distributed inside OpenNOP.

  Original code Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org)

  Modifications Copyright (C) 2014 Center for Open Middleware (COM)
                                   Universidad Politecnica de Madrid, SPAIN

  Modifications description: Some modifications done to include and handle per worker dictionaries

    OpenNOP is an open source Linux based network accelerator designed 
    to optimise network traffic over point-to-point, partially-meshed and 
    full-meshed IP networks.

    OpenNOP-SoloWAN is an enhanced version of the Open Network Optimization
    Platform (OpenNOP) developed to add it deduplication capabilities using
    a modern dictionary based compression algorithm.

    SoloWAN is a project of the Center for Open Middleware (COM) of Universidad
    Politecnica de Madrid which aims to experiment with open-source based WAN
    optimization solutions.

  References:

    OpenNOP: http://www.opennop.org
    SoloWAN: solowan@centeropenmiddleware.com
             https://github.com/centeropenmiddleware/solowan/wiki
    Center for Open Middleware (COM): http://www.centeropenmiddleware.com
    Universidad Politecnica de Madrid (UPM): http://www.upm.es

  License:

    OpenNOP and OpenNOP-SoloWAN are free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenNOP and OpenNOP-SoloWAN are distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h> // for multi-threading
#include <netinet/ip.h> // for tcpmagic and TCP options
#include <netinet/tcp.h> // for tcpmagic and TCP options
#include <linux/types.h>
#include <linux/netfilter.h> // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h> // for access to Netfilter Queue
#include "queuemanager.h"
#include "worker.h"
#include "opennopd.h"
#include "packet.h"
#include "compression.h"
#include "csum.h"
#include "sessionmanager.h"
#include "tcpoptions.h"
#include "logger.h"
#include "quicklz.h"
#include "memorymanager.h"
#include "counters.h"
#include "climanager.h"

#include "deduplication.h"

struct worker workers[MAXWORKERS]; // setup slots for the max number of workers.
unsigned char numworkers = 0; // sets number of worker threads. 0 = auto detect.
int DEBUG_OPTIMIZATION = false;
int DEBUG_WORKER = false;
int DEBUG_WORKER_CLI = false;
int DEBUG_WORKER_COUNTERS = false;

void *optimization_thread(void *dummyPtr) {
	struct worker *me = NULL;
	struct packet *thispacket = NULL;
	struct session *thissession = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	__u32 largerIP, smallerIP, remoteID;
	__u16 largerIPPort, smallerIPPort;
	char message[LOGSZ];
	qlz_state_compress *state_compress = (qlz_state_compress *) malloc(sizeof(qlz_state_compress));
	me = dummyPtr;

	me->optimization.lzbuffer = calloc(1, BUFSIZE + 400);
	/* Sharwan J: QuickLZ buffer needs (original data size + 400 bytes) buffer */
	if (me->optimization.lzbuffer == NULL) {
		sprintf(message, "Worker optimization: Couldn't allocate buffer lzbuffer");
		logger(LOG_INFO, message);
		exit(1);
	}

	me->optimization.dedup_buffer = calloc(1, 2*BUFSIZE + 400);
	/* Solowan deduplication needs (original size + 400) buffer */
	if (me->optimization.dedup_buffer == NULL) {
		sprintf(message, "Worker optimization: Couldn't allocate buffer dedup");
		logger(LOG_INFO, message);
		exit(1);
	}

	/*
	 * Register the worker threads metrics so they get updated.
	 */
	register_counter(counter_updateworkermetrics, (t_counterdata)
			& me->optimization.metrics);

	if (me->optimization.dedup_buffer != NULL) {

		while (me->state >= STOPPING) {

			thispacket = dequeue_packet(&me->optimization.queue, true);

			if(compression == true || deduplication == true){

				if (thispacket != NULL) { // If a packet was taken from the queue.
					iph = (struct iphdr *) thispacket->data;
					tcph = (struct tcphdr *) (((u_int32_t *) iph) + iph->ihl);

					if (DEBUG_WORKER == true) {
						sprintf(message, "Worker: IP Packet length is: %u\n",
								ntohs(iph->tot_len));
						logger(LOG_INFO, message);
					}
					me->optimization.metrics.bytesin += ntohs(iph->tot_len);
					remoteID = (__u32) __get_tcp_option((__u8 *)iph,32);/* Check what IP address is larger. */
					sort_sockets(&largerIP, &largerIPPort, &smallerIP, &smallerIPPort,
							iph->saddr,tcph->source,iph->daddr,tcph->dest);

					if (DEBUG_WORKER == true)
					{
						sprintf(message, "Worker: Searching for session.\n");
						logger(LOG_INFO, message);
					}

					thissession = getsession(largerIP, largerIPPort, smallerIP,smallerIPPort);

					if (thissession != NULL)
					{

						if (DEBUG_WORKER == true)
						{
							sprintf(message, "Worker: Found a session.\n");
							logger(LOG_INFO, message);
						}

						if ((tcph->syn == 0) && (tcph->ack == 1) && (tcph->fin == 0))
						{

							if (remoteID == 0)
							{ // Accelerator ID was not found.

								saveacceleratorid(largerIP, localID, iph, thissession);

								__set_tcp_option((__u8 *)iph,32,6,localID); // Add the Accelerator ID to this packet.

								if ((((iph->saddr == largerIP) &&
										(thissession->largerIPAccelerator == localID) &&
										(thissession->smallerIPAccelerator != 0) &&
										(thissession->smallerIPAccelerator != localID)) ||

										((iph->saddr == smallerIP) &&
												(thissession->smallerIPAccelerator == localID) &&
												(thissession->largerIPAccelerator != 0) &&
												(thissession->largerIPAccelerator != localID))) &&
										(thissession->state == TCP_ESTABLISHED))
								{

									/*
									 * Do some acceleration!
									 */

									if (DEBUG_WORKER == true)
									{
										sprintf(message, "Worker: Compressing packet.\n");
										logger(LOG_INFO, message);
									}

									if(compression == true){
										tcp_compress((__u8 *)iph, me->optimization.lzbuffer,state_compress);
									}

									if(deduplication == true){
										// Check Sequence Number to detect retransmission (or out of order segment)
										if(checkseqnumber(largerIP, iph, tcph, thissession)){
											updateseqnumber(largerIP, iph, tcph, thissession);
											// printf("Before tcp_optimize worker %d\n",me->workernum);
											tcp_optimize(me->compressor,(__u8 *)iph, me->optimization.dedup_buffer);
										}else{
											if (DEBUG_OPTIMIZATION == true)
											{
												sprintf(message, "Worker: Packet not optimized.\n");
												logger(LOG_INFO, message);
											}
											// printf("Before tcp_cache_optim worker %d\n",me->workernum);
											tcp_cache_optim(me->compressor,(__u8 *)iph);
										}
									}
								}
								else
								{
									if (DEBUG_WORKER == true)
									{
										sprintf(message, "Worker: Not compressing packet.\n");
										logger(LOG_INFO, message);
									}
									if(deduplication == true){
										updateseqnumber(largerIP, iph, tcph, thissession);
										// printf("Before tcp_cache_optim worker %d\n",me->workernum);
										tcp_cache_optim(me->compressor,(__u8 *)iph); // We cache it anyway
									}
								}
							}
						}

						if (tcph->rst == 1)
						{ // Session was reset.

							if (DEBUG_WORKER == true)
							{
								sprintf(message, "Worker: Session was reset.\n");
								logger(LOG_INFO, message);
							}
							clearsession(thissession);
							thissession = NULL;
						}

						closingsession(tcph, thissession);

						if (thispacket != NULL)
						{
							/*
							 * Changing anything requires the IP and TCP
							 * checksum to need recalculated.
							 */

							checksum(thispacket->data);
							me->optimization.metrics.bytesout += ntohs(iph->tot_len);
							nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, ntohs(iph->tot_len), (unsigned char *)thispacket->data);
							put_freepacket_buffer(thispacket);
							thispacket = NULL;
						}

					} /* End NULL session check. */
					else
					{ /* Session was NULL. */
						me->optimization.metrics.bytesout += ntohs(iph->tot_len);
						nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, 0, NULL);
						put_freepacket_buffer(thispacket);
						thispacket = NULL;
					}
					me->optimization.metrics.packets++;
				} /* End NULL packet check. */
			} /* End compression enabled check. */
			else
			{  /* Compression is disabled */
				nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, 0, NULL);
				put_freepacket_buffer(thispacket);
				thispacket = NULL;
			}
		} /* End working loop. */
		free(me->optimization.lzbuffer);
		free(me->optimization.dedup_buffer);
		free(state_compress);
		me->optimization.lzbuffer = NULL;
		me->optimization.dedup_buffer = NULL;
	}
	return NULL;
}

void *deoptimization_thread(void *dummyPtr) {
	struct worker *me = NULL;
	struct packet *thispacket = NULL;
	struct session *thissession = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	__u32 largerIP, smallerIP, remoteID;
	__u16 largerIPPort, smallerIPPort;
	char message[LOGSZ];
	qlz_state_decompress *state_decompress = (qlz_state_decompress *) malloc(
			sizeof(qlz_state_decompress));
	me = dummyPtr;
	int result = 0;

	me->deoptimization.lzbuffer = calloc(1, BUFSIZE + 400);
	/* Sharwan J: QuickLZ buffer needs (original data size + 400 bytes) buffer */
	if (me->deoptimization.lzbuffer == NULL) {
		sprintf(message, "Worker:deoptimization Couldn't allocate buffer lzbuffer\n");
		logger(LOG_INFO, message);
		exit(1);
	}

	me->deoptimization.dedup_buffer = calloc(1, 2*BUFSIZE + 400);
	/* Solowan deduplication needs a utility buffer */
	if (me->deoptimization.dedup_buffer == NULL) {
		sprintf(message, "Worker deoptimization: Couldn't allocate buffer dedup\n");
		logger(LOG_INFO, message);
		exit(1);
	}

	/*
	 * Register the worker threads metrics so they get updated.
	 */
	register_counter(counter_updateworkermetrics, (t_counterdata)
			& me->deoptimization.metrics);

	if (me->deoptimization.dedup_buffer != NULL && me->deoptimization.lzbuffer != NULL) {

		while (me->state >= STOPPING) {

			thispacket = dequeue_packet(&me->deoptimization.queue, true);

			if (thispacket != NULL) { // If a packet was taken from the queue.
				iph = (struct iphdr *) thispacket->data;
				tcph = (struct tcphdr *) (((u_int32_t *) iph) + iph->ihl);

				if (DEBUG_WORKER == true) {
					sprintf(message, "Worker: IP Packet length is: %u\n",
							ntohs(iph->tot_len));
					logger(LOG_INFO, message);
				}
				me->deoptimization.metrics.bytesin += ntohs(iph->tot_len);
				remoteID = (__u32) __get_tcp_option((__u8 *)iph,32);/* Check what IP address is larger. */
				sort_sockets				(&largerIP, &largerIPPort, &smallerIP, &smallerIPPort,
						iph->saddr,tcph->source,iph->daddr,tcph->dest);

				if (DEBUG_WORKER == true)
				{
					sprintf(message, "Worker: Searching for session.\n");
					logger(LOG_INFO, message);
				}

				thissession = getsession(largerIP, largerIPPort, smallerIP,smallerIPPort);

				if (thissession != NULL)
				{

					if (DEBUG_WORKER == true)
					{
						sprintf(message, "Worker: Found a session.\n");
						logger(LOG_INFO, message);
					}

					if ((tcph->syn == 0) && (tcph->ack == 1) && (tcph->fin == 0))
					{

						if (remoteID != 0){

							saveacceleratorid(largerIP, remoteID, iph, thissession);

							if (__get_tcp_option((__u8 *)iph,31) != 0)
							{ // Packet is flagged as compressed.

								if (DEBUG_WORKER == true)
								{
									sprintf(message, "Worker: Packet is deduplicated.\n");
									logger(LOG_INFO, message);
								}

								if (((iph->saddr == largerIP) &&
										(thissession->smallerIPAccelerator == localID)) ||
										((iph->saddr == smallerIP) &&
												(thissession->largerIPAccelerator == localID)))
								{

									/*
									 * Decompress this packet!
									 */
									if(compression == true){
										if (tcp_decompress((__u8 *)iph, me->deoptimization.lzbuffer, state_decompress) == 0)
										{ // Decompression failed if 0.
											nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP, 0, NULL); // Decompression failed drop.
											put_freepacket_buffer(thispacket);
											thispacket = NULL;
										}
									}

									if (deduplication == true){
										updateseqnumber(largerIP, iph, tcph, thissession);
										// printf("Before tcp_deoptimize worker %d\n",me->workernum);
										result = tcp_deoptimize(me->decompressor,(__u8 *)iph, me->deoptimization.dedup_buffer);
										if (result == ERROR)
										{ // Decompression failed if 0.
											nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP, 0, NULL); // Decompression failed drop.
											put_freepacket_buffer(thispacket);
											thispacket = NULL;
										}else if(result == HASH_NOT_FOUND){
											nfq_set_verdict(thispacket->hq, thispacket->id, NF_DROP, 0, NULL); // Decompression failed drop.
											put_freepacket_buffer(thispacket);
											thispacket = NULL;
										}
									}

								}
							}else{
								if (deduplication == true){
									//We must cache packets even if they are not compressed
									// printf("Before tcp_cache_deoptim worker %d\n",me->workernum);
									tcp_cache_deoptim(me->decompressor,(__u8 *)iph);
								}
							}
						}
					}

					if (tcph->rst == 1)
					{ // Session was reset.

						if (DEBUG_WORKER == true)
						{
							sprintf(message, "Worker: Session was reset.\n");
							logger(LOG_INFO, message);
						}
						clearsession(thissession);
						thissession = NULL;
					}

					closingsession(tcph, thissession);

					if (thispacket != NULL)
					{
						/*
						 * Changing anything requires the IP and TCP
						 * checksum to need recalculated.
						 */
						checksum(thispacket->data);
						me->deoptimization.metrics.bytesout += ntohs(iph->tot_len);
						nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, ntohs(iph->tot_len), (unsigned char *)thispacket->data);
						put_freepacket_buffer(thispacket);
						thispacket = NULL;
					}

				} /* End NULL session check. */
				else
				{ /* Session was NULL. */
					me->deoptimization.metrics.bytesout += ntohs(iph->tot_len);
					nfq_set_verdict(thispacket->hq, thispacket->id, NF_ACCEPT, 0, NULL);
					put_freepacket_buffer(thispacket);
					thispacket = NULL;
				}
				me->deoptimization.metrics.packets++;
			} /* End NULL packet check. */
		} /* End working loop. */
		free(me->deoptimization.lzbuffer);
		free(me->deoptimization.dedup_buffer);
		free(state_decompress);
		me->deoptimization.lzbuffer = NULL;
		me->deoptimization.dedup_buffer = NULL;
	}
	return NULL;
}

/*
 * Returns how many workers should be running.
 */
unsigned char get_workers(void) {
	return numworkers;
}

/*
 * Sets how many workers should be running.
 */
void set_workers(unsigned char desirednumworkers) {
	numworkers = desirednumworkers;
}

u_int32_t get_worker_sessions(int i) {
	u_int32_t sessions;
	pthread_mutex_lock(&workers[i].lock);
	sessions = workers[i].sessions;
	pthread_mutex_unlock(&workers[i].lock);
	return sessions;
}

void increment_worker_sessions(int i) {

	pthread_mutex_lock(&workers[i].lock); // Grab lock on worker.
	workers[i].sessions += 1;
	pthread_mutex_unlock(&workers[i].lock); // Lose lock on worker.
}
void decrement_worker_sessions(int i) {
	pthread_mutex_lock(&workers[i].lock); // Grab lock on worker.
	workers[i].sessions -= 1;
	pthread_mutex_unlock(&workers[i].lock); // Lose lock on worker.
}

void create_worker(int i) {
	initialize_worker_processor(&workers[i].optimization);
	initialize_worker_processor(&workers[i].deoptimization);
	workers[i].workernum = i;
	workers[i].compressor = newDeduplicator();
	workers[i].decompressor = newDeduplicator();
	workers[i].sessions = 0;
	pthread_mutex_init(&workers[i].lock, NULL); // Initialize the worker lock.
	pthread_create(&workers[i].optimization.t_processor, NULL,
			optimization_thread, (void *) &workers[i]);
	pthread_create(&workers[i].deoptimization.t_processor, NULL,
			deoptimization_thread, (void *) &workers[i]);
	set_worker_state_running(&workers[i]);
}

void set_worker_state_stopping(struct worker *thisworker) {
	pthread_mutex_lock(&thisworker->lock);
	thisworker->state = STOPPING;
	pthread_mutex_unlock(&thisworker->lock);
}

void shutdown_workers() {
	int i;
	for (i = 0; i < get_workers(); i++) {
		pthread_cond_signal(&workers[i].optimization.queue.signal);
		pthread_cond_signal(&workers[i].deoptimization.queue.signal);
		//		set_worker_state_stopping(i);
	}
}

void rejoin_worker(int i) {
	joining_worker_processor(&workers[i].optimization);
	joining_worker_processor(&workers[i].deoptimization);
	set_worker_state_stopped(&workers[i]);
}

void initialize_worker_processor(struct processor *thisprocessor) {
	pthread_cond_init(&thisprocessor->queue.signal, NULL); // Initialize the thread signal.
	thisprocessor->queue.next = NULL; // Initialize the queue.
	thisprocessor->queue.prev = NULL;
	thisprocessor->lzbuffer = NULL;
	thisprocessor->dedup_buffer = NULL;
	thisprocessor->queue.qlen = 0;
	pthread_mutex_init(&thisprocessor->queue.lock, NULL); // Initialize the queue lock.
}

void joining_worker_processor(struct processor *thisprocessor) {
	pthread_mutex_lock(&thisprocessor->queue.lock);
	pthread_cond_signal(&thisprocessor->queue.signal);
	pthread_mutex_unlock(&thisprocessor->queue.lock);
	pthread_join(thisprocessor->t_processor, NULL);
}

void set_worker_state_running(struct worker *thisworker) {
	pthread_mutex_lock(&thisworker->lock);
	thisworker->state = RUNNING;
	pthread_mutex_unlock(&thisworker->lock);
}

void set_worker_state_stopped(struct worker *thisworker) {
	pthread_mutex_lock(&thisworker->lock);
	thisworker->state = STOPPED;
	pthread_mutex_unlock(&thisworker->lock);
}

int optimize_packet(__u8 queue, struct packet *thispacket) {
	return queue_packet(&workers[queue].optimization.queue, thispacket);
}

int deoptimize_packet(__u8 queue, struct packet *thispacket) {
	return queue_packet(&workers[queue].deoptimization.queue, thispacket);
}

int cli_show_workers(int client_fd, char **parameters, int numparameters) {
	int i;
	__u32 ppsbps;
	__u32 total_optimization_pps = 0, total_optimization_bpsin = 0,
			total_optimization_bpsout = 0;
	__u32 total_deoptimization_pps = 0, total_deoptimization_bpsin = 0,
			total_deoptimization_bpsout = 0;
	char msg[MAX_BUFFER_SIZE] = { 0 };
	char message[LOGSZ];
	char bps[11];
	char optimizationbpsin[9];
	char optimizationbpsout[9];
	char deoptimizationbpsin[9];
	char deoptimizationbpsout[9];
	char col1[11];
	char col2[9];
	char col3[14];
	char col4[14];
	char col5[9];
	char col6[14];
	char col7[14];
	char col8[3];

	if (DEBUG_WORKER_CLI == true) {
		sprintf(message, "Counters: Showing counters");
		logger(LOG_INFO, message);
	}

	sprintf(
			msg,
			"-------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"|  5 sec  |          optimization           |          deoptimization         |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"-------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"|  worker |  pps  |     in     |     out    |  pps  |     in     |     out    |\n");
	cli_send_feedback(client_fd, msg);
	sprintf(
			msg,
			"-------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

	for (i = 0; i < get_workers(); i++) {

		strcpy(msg, "");

		sprintf(col1, "|    %-5i", i);
		strcat(msg, col1);

		ppsbps = workers[i].optimization.metrics.pps;
		total_optimization_pps += ppsbps;
		sprintf(col2, "| %-6u", ppsbps);
		strcat(msg, col2);

		ppsbps = workers[i].optimization.metrics.bpsin;
		total_optimization_bpsin += ppsbps;
		bytestostringbps(bps, ppsbps);
		sprintf(col3, "| %-11s", bps);
		strcat(msg, col3);

		ppsbps = workers[i].optimization.metrics.bpsout;
		total_optimization_bpsout += ppsbps;
		bytestostringbps(bps, ppsbps);
		sprintf(col4, "| %-11s", bps);
		strcat(msg, col4);

		ppsbps = workers[i].deoptimization.metrics.pps;
		total_deoptimization_pps += ppsbps;
		sprintf(col5, "| %-6u", ppsbps);
		strcat(msg, col5);

		ppsbps = workers[i].deoptimization.metrics.bpsin;
		total_deoptimization_bpsin += ppsbps;
		bytestostringbps(bps, ppsbps);
		sprintf(col6, "| %-11s", bps);
		strcat(msg, col6);

		ppsbps = workers[i].deoptimization.metrics.bpsout;
		total_deoptimization_bpsout += ppsbps;
		bytestostringbps(bps, ppsbps);
		sprintf(col7, "| %-11s", bps);
		strcat(msg, col7);

		sprintf(col8, "|\n");
		strcat(msg, col8);
		cli_send_feedback(client_fd, msg);
	}
	sprintf(
			msg,
			"-------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

	bytestostringbps(optimizationbpsin, total_optimization_bpsin);
	bytestostringbps(optimizationbpsout, total_optimization_bpsout);
	bytestostringbps(deoptimizationbpsin, total_deoptimization_bpsin);
	bytestostringbps(deoptimizationbpsout, total_deoptimization_bpsout);
	sprintf(msg, "|  total  | %-6u| %-11s| %-11s| %-6u| %-11s| %-11s|\n",
			total_optimization_pps, optimizationbpsin, optimizationbpsout,
			total_deoptimization_pps, deoptimizationbpsin, deoptimizationbpsout);
	cli_send_feedback(client_fd, msg);

	sprintf(
			msg,
			"-------------------------------------------------------------------------------\n");
	cli_send_feedback(client_fd, msg);

	return 0;
}

void counter_updateworkermetrics(t_counterdata data) {
	struct workercounters *metrics;
	char message[LOGSZ];
	__u32 counter;

	if (DEBUG_WORKER_COUNTERS == true)
	{
		sprintf(message, "Worker: Updating metrics!\n");
		logger(LOG_INFO, message);
	}

	metrics = (struct workercounters*) data;
	counter = metrics->packets;
	metrics->pps = calculate_ppsbps(metrics->packetsprevious, counter);
	metrics->packetsprevious = counter;

	counter = metrics->bytesin;
	metrics->bpsin = calculate_ppsbps(metrics->bytesinprevious, counter);
	metrics->bytesinprevious = counter;

	counter = metrics->bytesout;
	metrics->bpsout = calculate_ppsbps(metrics->bytesoutprevious, counter);
	metrics->bytesoutprevious = counter;

}

struct session *closingsession(struct tcphdr *tcph, struct session *thissession) {
	char message[LOGSZ];

	if ((tcph != NULL) && (thissession != NULL)) {

		/* Normal session closing sequence. */
		if (tcph->fin == 1) {

			if (DEBUG_WORKER == true) {
				sprintf(message, "Worker: Session is closing.\n");
				logger(LOG_INFO, message);
			}

			switch (thissession->state) {
			case TCP_ESTABLISHED:
				thissession->state = TCP_CLOSING;
				return thissession;

			case TCP_CLOSING:
				clearsession(thissession);
				thissession = NULL;
				return thissession;
			}
			return thissession; //Session not in good state!
		}
		return thissession; //Not a fin packet.
	}
	return thissession; // Something went very wrong!
}

pDeduplicator get_worker_compressor(int i) {
	return workers[i].compressor;
}

pDeduplicator get_worker_decompressor(int i) {
	return workers[i].decompressor;
}

