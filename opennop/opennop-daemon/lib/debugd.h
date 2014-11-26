/*
 *         Email: javier.ruiz@centeropenmiddleware.com
 *         Email: german.martin@centeropenmiddleware.com
 *         Statistics and trace header file.
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


