/*

  debugd.h

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

#include <inttypes.h>
#define SOLOWAN_DEBUGD_PORT 666
extern uint64_t debugword;
#define UPDATE_CACHE_MASK 0x3
#define LOCAL_UPDATE_CACHE_MASK 0xC
#define UPDATE_CACHE_RTX_MASK 0x30
#define DEDUP_MASK 0xC0
#define PUT_IN_CACHE_MASK 0x300
#define UNCOMP_MASK 0xC00

#define SET_DCMD "SETD"
#define GET_DCMD "GETD"
#define ORR_DCMD "ORRD"
#define AND_DCMD "ANDD"
#define NAND_DCMD "NAND"
#define RSTC_SCMD "RSTC"
#define RSTD_SCMD "RSTD"
#define GSTC_SCMD "GSTC"
#define GSTD_SCMD "GSTD"
#define QUIT_DCMD "QUIT"

#if !defined (_FUNCTION_DEF)
#  define _FUNCTION_DEF

typedef char *Function ();

#endif

typedef struct {
  char *name;                   /* User printable name of the function. */
  Function *func;		/* Function to call to do the job. */
  char *doc;                    /* Documentation for this function.  */
} COMMAND;

COMMAND *find_cli_command ();


typedef struct {
  char *name;			/* Name of the command. */
  uint64_t mask;
  char *doc;			/* Description of the command.  */
  int offset_bits;
} TRACECOMMAND;

TRACECOMMAND *find_trace_command (char* name);

int cli_show_traces_mask(int client_fd, char **parameters, int numparameters);
int cli_traces_mask_orr(int client_fd, char **parameters, int numparameters);
int cli_traces_mask_and(int client_fd, char **parameters, int numparameters);
int cli_traces_mask_nand(int client_fd, char **parameters, int numparameters);

int cli_traces_enable(int client_fd, char **parameters, int numparameters);

int cli_traces_disable(int client_fd, char **parameters, int numparameters);


