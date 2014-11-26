/*

  solowan_basic.h

  This file is part of OpenNOP-SoloWAN distribution.

  Copyright (C) 2014 Center for Open Middleware (COM) 
                     Universidad Politecnica de Madrid, SPAIN

    OpenNOP-SoloWAN is an enhanced version of the Open Network Optimization 
    Platform (OpenNOP) developed to add it deduplication capabilities using
    a modern dictionary based compression algorithm. 

    SoloWAN is a project of the Center for Open Middleware (COM) of Universidad 
    Politecnica de Madrid which aims to experiment with open-source based WAN 
    optimization solutions.

  References:

    SoloWAN: solowan@centeropenmiddleware.com
             https://github.com/centeropenmiddleware/solowan/wiki
    OpenNOP: http://www.opennop.org
    Center for Open Middleware (COM): http://www.centeropenmiddleware.com
    Universidad Politecnica de Madrid (UPM): http://www.upm.es   

  License:

    OpenNOP-SoloWAN is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenNOP-SoloWAN is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef SOLOWAN_BASIC_H_
#define SOLOWAN_BASIC_H_

int optimize(__u8 *in_packet, __u16 in_packet_size, __u8 *out_packet, __u16 *out_packet_size);
int deoptimize(__u8 *input_packet_ptr, __u16 input_packet_size, __u8 *regenerated_packet, __u16 *output_packet_size);
int cache(__u8 *packet_ptr, __u16 packet_size);

#endif /* SOLOWAN_BASIC_H_ */
