#ifndef	_CLI_MANAGER_H_
#define	_CLI_MANAGER_H_

#include <stdint.h>

#include <linux/types.h>

#include "clicommands.h"
#include "clisocket.h"

#define CLI_ERROR	-1
#define CLI_SUCCESS	0
#define CLI_SHUTDOWN	1
#define CLI_INV_CMD	2
#define CLI_ERR_CMD	3

#define END_OF_COMMAND 	"EOC"

int cli_process_message(int client_fd, char *buffer, int d_len);
void start_cli_server();
void *cli_manager_init(void *dummyPtr);
void *client_handler(void *socket_desc);

int num_sock;
int num_tot_sock;

#endif
