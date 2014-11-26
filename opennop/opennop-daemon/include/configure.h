/*
 * configure.h
 *
 *  Created on: Nov 5, 2013
 *      Author: mattia
 */

#ifndef CONFIGURE_H_
#define CONFIGURE_H_

/*
 * Receives he path of the configuration file and configures
 * optimization parameters. The default path is /etc/opennop/opennop.conf
 */
int configure(char *path, __u32 *localID, __u32 *packet_number, __u32 *packet_size, __u32 *thr_num);

#endif /* CONFIGURE_H_ */
