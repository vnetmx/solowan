/*
 * dedup_common.c
 *
 *     Copyright 2014 Universidad Politécnica de Madrid - Center for Open Middleware
 *     (http://www.centeropenmiddleware.com)
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 *         Email: javier.ruiz@centeropenmiddleware.com
 *         This file contains common functions to all deduplication library files.
 *
 * The implementation of De-duplication is based on the algorithm described in:
 * A Protocol-Independent Technique for Eliminating Redundant Network Traffic.
 * Neil T. Spring and David Wetherall.
 * Proceedings SIGCOMM '00
 * Proceedings of the conference on Applications, Technologies, Architectures, and Protocols for Computer Communication.
 * READ THAT ARTICLE BEFORE TRYING TO UNDERSTAND THIS CODE
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <pthread.h>

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include "solowan_rolling.h"
#include "MurmurHash3.h"
#include "logger.h"
#include "debugd.h"

static uint64_t fpfactors[BYTE_RANGE][BETA];
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int MAXPKTSIZE;
static unsigned int PKTSTORESIZE;
static unsigned int FPSTORESIZE;

inline void hton16(unsigned char *p, uint16_t n) {
	*p++ = (n >> 8) & 0xff;
	*p = n & 0xff;
}

inline void hton32(unsigned char *p, uint32_t n) {
	*p++ = (n >> 24) & 0xff;
	*p++ = (n >> 16) & 0xff;
	*p++ = (n >> 8) & 0xff;
	*p = n & 0xff;
}

inline void hton64(unsigned char *p, uint64_t n) {
	*p++ = (n >> 56) & 0xff;
	*p++ = (n >> 48) & 0xff;
	*p++ = (n >> 40) & 0xff;
	*p++ = (n >> 32) & 0xff;
	*p++ = (n >> 24) & 0xff;
	*p++ = (n >> 16) & 0xff;
	*p++ = (n >> 8) & 0xff;
	*p = n & 0xff;
}

inline uint16_t ntoh16(unsigned char *p) {
        uint16_t res = *p++;
        return (res << 8) + *p;
}

inline uint32_t ntoh32(unsigned char *p) {
        uint32_t res = *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        return res;
}

inline uint64_t ntoh64(unsigned char *p) {
        uint64_t res = *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        res = (res << 8) + *p++;
        return res;
}

inline uint32_t hashFPStore(uint64_t fp) {

    uint32_t h1, h2, h3, h4 ;
    fp = fp >> GAMMA;
    h1 = (uint32_t) (fp & 0xffffffff);
    h2 = (uint32_t) ((fp >> 32) & 0xffffffff);
    h3 = h1 ^ h2;
    h4 = h3 & (FPSTORESIZE-1);
    return h4 ^ (h3 >> 24);

}

// Full calculation of the initial Rabin fingerprint
inline static uint64_t full_rfp(unsigned char *p) {
	int i;
	uint64_t fp = 0;
	for (i=0;i<BETA;i++) {
		fp = (fp + fpfactors[p[i]][BETA-i-1]) & MOD_MASK;
	}
	return fp;
}

// Incremental calculation of a Rabin fingerprint
inline static uint64_t inc_rfp(uint64_t prev_fp, unsigned char new, unsigned char dropped) {
	uint64_t fp;
	fp = ((prev_fp - fpfactors[dropped][BETA-1])*P + new) & MOD_MASK;
	return fp;

}

// Auxiliary table for calculating fingerprints
static uint64_t fpfactors[BYTE_RANGE][BETA];

void init_common(unsigned int pktStoreSize, unsigned int pktSize) {

	int i,j;

	pthread_mutex_lock(&mutex);
        	MAXPKTSIZE = pktSize;
        	PKTSTORESIZE = pktStoreSize;
        	FPSTORESIZE = (MAX_FP_PER_PKT*PKTSTORESIZE*FPS_FACTOR);

        	// Initialize auxiliary table for calculating fingerprints
        	for (i=0; i<BYTE_RANGE; i++) {
                	fpfactors[i][0] = i;
                	for (j=1; j<BETA; j++) {
                        	fpfactors[i][j] = (fpfactors[i][j-1]*P) & MOD_MASK;
                	}
        	}
	pthread_mutex_unlock(&mutex);

}

inline unsigned int MAX_PKT_SIZE(void) {return MAXPKTSIZE;}
inline unsigned int PKT_STORE_SIZE(void) {return PKTSTORESIZE;}
inline unsigned int FP_STORE_SIZE(void) {return FPSTORESIZE;}

unsigned int calculateRelevantFPs(FPEntryB *pktFps, unsigned char *packet, uint16_t pktlen) {

        uint64_t selectFPmask;
        uint64_t tentativeFP;
        int exploring, previous;
        int endLoop;
        unsigned int fpNum = 1;
        int iter = 0;

        // Calculate initial fingerprint
        pktFps[0].fp = full_rfp(packet);
        pktFps[0].offset = 0;

        selectFPmask = SELECT_FP_MASK;

        // Calculate other relevant fingerprints
        tentativeFP = pktFps[0].fp;
        previous = exploring = BETA;
        endLoop = (exploring >= pktlen);
        while (!endLoop) {
                tentativeFP = inc_rfp(tentativeFP, packet[exploring], packet[exploring-BETA]);
                if (((tentativeFP & selectFPmask) == 0) && (exploring - previous >= BETA/2)) {
                        previous = exploring;
                        pktFps[fpNum].fp = tentativeFP;
                        pktFps[fpNum].offset = exploring-BETA+1;
                        fpNum++;
                }
                if (++exploring >= pktlen) {
                        if ((fpNum < MAX_FP_PER_PKT) && (iter < MAX_ITER)) {
                                tentativeFP = pktFps[0].fp;
                                previous = exploring = BETA;
                                selectFPmask = selectFPmask << 1;
                                iter++;
                        } else endLoop = 1;
                } else endLoop = (fpNum == MAX_FP_PER_PKT);
        }
        return fpNum;
}

// UNSAFE FUNCTION, must be called inside code with locks
// getFPhash returns the FPEntryB given the FPStore, the PStore, the FP and the packet hash (returns NULL if not found) 
inline FPEntryB *getFPhash(FPStore fpStore, PktStore *pktStore, uint64_t fp, uint32_t pktHash) {
	uint32_t fpHash;
	FPEntry *fpp;
	int bkt;
	PktEntry *pkt;

	fpHash = hashFPStore(fp);
	fpp = &fpStore[fpHash];
	for (bkt=0;bkt<PKTS_PER_FP;bkt++) {
		if (fpp->pkts[bkt].fp == fp) {
			pkt = getPkt(pktStore, fpp->pkts[bkt].pktId);
			if ((pkt != NULL) && (pkt->hash == pktHash)) break;
		}
	}
	if (bkt == PKTS_PER_FP) return (FPEntryB *) NULL; // Not found
	else return &fpp->pkts[bkt];
}

// UNSAFE FUNCTION, must be called inside code with locks
// getFPcontent returns the FPEntryB given the FPStore, the PStore, the FP and the packet chunk (returns NULL if not found) 
inline FPEntryB *getFPcontent(FPStore fpStore, PktStore *pktStore, uint64_t fp, unsigned char *chunk) {
	FPEntry *fpp;
	uint32_t fpHash;
	int bkt;
	PktEntry *pkt;

	fpHash = hashFPStore(fp);
	fpp = &fpStore[fpHash];
	for (bkt=0;bkt<PKTS_PER_FP;bkt++) {
		if ((fpp->pkts[bkt].pktId > 0) && (fpp->pkts[bkt].fp == fp)) {
			pkt = getPkt(pktStore, fpp->pkts[bkt].pktId);
			if ((pkt != NULL) && !memcmp(chunk,pkt->pkt+fpp->pkts[bkt].offset,BETA)) break;
		}
	}
	if (bkt == PKTS_PER_FP) return (FPEntryB *) NULL; // Not found
	else return &fpp->pkts[bkt];
}

// UNSAFE FUNCTION, must be called inside code with locks
inline PktEntry *getPkt(PktStore *pktStore, int64_t pktId) {
	if (pktStore->pktId < pktId) return NULL;
	if (pktId < pktStore->pktId - PKTSTORESIZE) return NULL;
	return &pktStore->pkts[pktId % PKTSTORESIZE];
}

// UNSAFE FUNCTION, must be called inside code with locks
inline PktEntry *getPktHash(PktStore *pktStore, uint32_t pktHash) {
#define BACKTRACELIM 1000
	int64_t idx = pktStore->pktId % PKTSTORESIZE;
	int curr = (int) idx;
	int i;
	if (idx >= BACKTRACELIM) {
		for (i = curr; i >= curr - BACKTRACELIM; i--) {
			if (pktStore->pkts[i].hash == pktHash) return &pktStore->pkts[i];
		}
	} else {
		for (i=curr; i >= 0; i--) {
			if (pktStore->pkts[i].hash == pktHash) return &pktStore->pkts[i];
		}
		for (i=PKTSTORESIZE-1; i >= PKTSTORESIZE-BACKTRACELIM+curr; i--) {
			if (pktStore->pkts[i].hash == pktHash) return &pktStore->pkts[i];
		}
	}
	return NULL;
}


// UNSAFE FUNCTION, must be called inside code with locks
inline int64_t putPkt(PktStore *pktStore, unsigned char *pkt, uint16_t pktlen, uint32_t pktHash) {
	int32_t pktIdx = (int32_t) (pktStore->pktId % PKTSTORESIZE);
	memcpy(pktStore->pkts[pktIdx].pkt, pkt, pktlen);
	pktStore->pkts[pktIdx].len = pktlen;
	pktStore->pkts[pktIdx].hash = pktHash;
	return pktStore->pktId++;
}

// UNSAFE FUNCTION, must be called inside code with locks
inline void putFP(FPStore fpStore, PktStore *pktStore, uint64_t fp, int64_t pktId, uint16_t offset, Statistics *st) {
	int fpidx;
	int emptyPos = PKTS_PER_FP;
	PktEntry *pktE, *pktEbis;
	uint32_t fpHash;
	FPEntry *fpp;

	fpHash = hashFPStore(fp);
	fpp = &fpStore[fpHash];

	for (fpidx = 0; fpidx < PKTS_PER_FP; fpidx++) {
 		if (fpp->pkts[fpidx].pktId < pktId - PKTSTORESIZE) fpp->pkts[fpidx].pktId = 0;
		if (fpp->pkts[fpidx].pktId == 0) emptyPos = fpidx;
	}

	// Search FP value
	for (fpidx = 0; fpidx < PKTS_PER_FP; fpidx++) {
		if (fpp->pkts[fpidx].fp == fp) break;
	}
	if (fpidx == PKTS_PER_FP) { // FP value not present in database, store if possible
		if (emptyPos < PKTS_PER_FP) {
			fpp->pkts[emptyPos].fp = fp;
			fpp->pkts[emptyPos].pktId = pktId;
			fpp->pkts[emptyPos].offset = offset;
			st->numOfFPEntries++;
		} else  { // All bucket filled, we call this FP Hash collisions
			st->numberOfFPHashCollisions++;
		}
	} else { // FP value present in database. Update if not FP collision, else store if possible.
		pktE = getPkt(pktStore,pktId);
		pktEbis = getPkt(pktStore,fpp->pkts[fpidx].pktId);
		if ((pktE != NULL) && (pktEbis != NULL) && !memcmp(pktEbis->pkt+fpp->pkts[fpidx].offset,pktE->pkt+offset,BETA)) { // Not FP collision, update
			fpp->pkts[fpidx].fp = fp;
			fpp->pkts[fpidx].pktId = pktId;
			fpp->pkts[fpidx].offset = offset;
		} else { // FP collision, store if possible
			if (emptyPos < PKTS_PER_FP) {
				fpp->pkts[emptyPos].fp = fp;
				fpp->pkts[emptyPos].pktId = pktId;
				fpp->pkts[emptyPos].offset = offset;
				st->numOfFPEntries++;
			}
		}

	}

}

// Initialization tasks
pDeduplicator newDeduplicator(void) {

        int i, j;
	
	pDeduplicator pd;
	
	pd = malloc(sizeof(Deduplicator));
	if (pd == NULL) {
		printf("Unable to allocate memory");
		abort();
	}

	// Packet Counter
	pd->ps.pktId = 1; // 0 means empty FPEntry
	// Packet store
 	pd->ps.pkts = malloc(PKT_STORE_SIZE()*sizeof(PktEntry));

        if (pd->ps.pkts == NULL) {
		printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
		abort();
	}
	
        for (i = 0; i < PKT_STORE_SIZE(); i++) {
                pd->ps.pkts[i].pkt = malloc(MAX_PKT_SIZE());
                if (pd->ps.pkts[i].pkt == NULL) {
			printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
			abort();
		}
        }
        pd->fps = malloc(FP_STORE_SIZE()*sizeof(FPEntry));
        if (pd->fps == NULL) {
		printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
		abort();
	}

        // Initialize FPStore
        for (i=0; i<FP_STORE_SIZE(); i++) {
                pd->fps[i].pkts = malloc(PKTS_PER_FP*sizeof(FPEntryB));
                if (pd->fps[i].pkts == NULL) {
			printf("Unable to allocate memory initializing hash table. Please, check num_pkt_cache_size value in opennop.conf\n");
			abort();
		}
                for (j=0; j<PKTS_PER_FP; j++) {
			pd->fps[i].pkts[j].pktId = 0;
			pd->fps[i].pkts[j].fp = UINT64_MAX;
                }
        }

	pthread_mutex_init(&pd->cerrojo, NULL);

	// Initialize statistics
	memset((void *) &pd->compStats, 0, sizeof(pd->compStats));
	return pd;

}

void getStatistics(pDeduplicator pd, Statistics *cs) {
	pthread_mutex_lock(&pd->cerrojo);
	*cs = pd->compStats;
	pthread_mutex_unlock(&pd->cerrojo);
}
void resetStatistics(pDeduplicator pd) {
	pthread_mutex_lock(&pd->cerrojo);
	memset(&pd->compStats,0,sizeof(pd->compStats));
	pthread_mutex_unlock(&pd->cerrojo);
}
