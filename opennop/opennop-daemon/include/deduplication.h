/*
 * deduplication.h
 *
 *  Created on: Nov 4, 2013
 *      Author: mattia
 */

#ifndef DEDUPLICATION_H_
#define DEDUPLICATION_H_

#include <linux/types.h>
#include <stdint.h>
#include "01dedup.h"
#include "solowan_rolling.h"

#define CHUNK 400
#define BUFFER_SIZE 1600

#define ERROR 0
#define OK 1
#define HASH_NOT_FOUND 2

typedef struct hashptr{
    uint16_t position;
    struct hashptr *next;
}hashptr;

extern hashtable ht;

int cli_reset_stats_in_dedup(int client_fd, char **parameters, int numparameters);
int cli_reset_stats_in_dedup_thread(int client_fd, char **parameters, int numparameters);
int cli_show_stats_in_dedup(int client_fd, char **parameters, int numparameters);
int cli_show_stats_in_dedup_thread(int client_fd, char **parameters, int numparameters);
int cli_reset_stats_out_dedup(int client_fd, char **parameters, int numparameters);
int cli_reset_stats_out_dedup_thread(int client_fd, char **parameters, int numparameters);
int cli_show_stats_out_dedup(int client_fd, char **parameters, int numparameters);
int cli_show_stats_out_dedup_thread(int client_fd, char **parameters, int numparameters);

int cli_show_deduplication(int client_fd, char **parameters, int numparameters);
int cli_deduplication_enable(int client_fd, char **parameters, int numparameters);
int cli_deduplication_disable(int client_fd, char **parameters, int numparameters);

unsigned int tcp_optimize(pDeduplicator pd, __u8 *ippacket, __u8 *buffered_packet);
unsigned int tcp_deoptimize(pDeduplicator pd, __u8 *ippacket, __u8 *buffered_packet);
unsigned int tcp_cache_deoptim(pDeduplicator pd, __u8 *ippacket);
unsigned int tcp_cache_optim(pDeduplicator pd, __u8 *ippacket);
int deduplication_enable();
int deduplication_disable();
extern int deduplication;

#endif /* DEDUPLICATION_H_ */
