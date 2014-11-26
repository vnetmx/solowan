/*

  counters.h

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
#ifndef COUNTERS_H_
#define COUNTERS_H_

#include <pthread.h>
#include <sys/time.h>
#include <linux/types.h>

typedef void *t_counterdata;
typedef void (*t_counterfunction)(t_counterdata);

struct counter_head {
	struct counter *next; // Points to the first command of the list.
	struct counter *prev; // Points to the last command of the list.
	pthread_mutex_t lock; // Lock for this node.
};

struct counter {
	struct counter *next;
	struct counter *prev;
	t_counterfunction handler;
	t_counterdata data; //Points to the metric structure.
};

void *counters_function(void *dummyPtr);
int calculate_ppsbps(__u32 previouscount, __u32 currentcount);
int register_counter(t_counterfunction, t_counterdata); //Adds a counter record to the counters head list.
int un_register_counter(t_counterfunction, t_counterdata); //Will remove a counter record.
struct counter* allocate_counter();
void execute_counters();

#endif /*COUNTERS_H_*/
