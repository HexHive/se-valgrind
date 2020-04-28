//
// Created by derrick on 3/8/20.
//

#ifndef SE_VALGRIND_SE_COMMAND_SERVER_H
#define SE_VALGRIND_SE_COMMAND_SERVER_H

#include "se_command.h"
#include "se_io_vec.h"

#ifndef VKI_POLLPRI
#define VKI_POLLPRI 0x0002
#endif
#ifndef VKI_POLLOUT
#define VKI_POLLOUT 0x0004
#endif
#ifndef VKI_POLLERR
#define VKI_POLLERR 0x0008
#endif
#ifndef VKI_POLLHUP
#define VKI_POLLHUP 0x0010
#endif
#ifndef VKI_POLLNVAL
#define VKI_POLLNVAL 0x0020
#endif

#define CLIENT_CODE_LOAD_ADDR 0x108000

typedef enum se_server_state {
  SERVER_INVALID,            /* Error State */
  SERVER_WAIT_FOR_START,     /* Server is initialized and ready to start */
  SERVER_START,              /* Server is starting */
  SERVER_WAIT_FOR_TARGET,    /* Server is waiting for a target function */
  SERVER_WAIT_FOR_CMD,       /* Server is waiting for a command */
  SERVER_FUZZING,            /* Server is fuzzing program state */
  SERVER_EXECUTING,          /* Server is executing target function */
  SERVER_EXIT,               /* Server is exiting */
  SERVER_REPORT_ERROR,       /* Server reported an error */
  SERVER_SETTING_CTX,        /* Server is establishing input program state */
  SERVER_WAITING_TO_EXECUTE, /* Server is ready to execute target function */
  SERVER_GETTING_INIT_STATE, /* The server is gathering the initial state */
} SE_(cmd_server_state);

typedef struct {
  SE_(cmd_server_state) current_state;
  Int commander_r_fd, commander_w_fd;
  Int running_pid;
  Addr target_func_addr;
  Addr main_addr;
  Int executor_pipe[2];
  Bool using_fuzzed_io_vec;
  Bool using_existing_io_vec;
  Bool added_client_code_offset;
  ThreadId executor_tid;
  UInt attempt_count;
  Addr initial_frame_ptr;
  Addr initial_stack_ptr;
  Addr min_stack_ptr;
  OSet *coverage;
  SE_(io_vec) * current_io_vec;
} SE_(cmd_server);

/**
 * @brief Reads the coverage of the last executed IOVec from the executor
 * @param server
 * @return
 */
OSet *SE_(read_coverage)(SE_(cmd_server) * server);

/**
 * @brief Initializes and returns a command server, and bails on failure
 * @param commander_r_fd - Commander read pipe file descriptor
 * @param commander_w_fd - Commander write pipe file descriptor
 * @return command server
 */
SE_(cmd_server) * SE_(make_server)(Int commander_r_fd, Int commander_w_fd);

/**
 * @brief Starts listening for commands
 * @param server
 * @param executorTid
 */
void SE_(start_server)(SE_(cmd_server) * server, ThreadId executor_tid);

/**
 * @brief Kills any running process, performs exiting tasks, and sets the
 * server status to SERVER_EXIT. Does not free the server.
 * @param server
 */
void SE_(stop_server)(SE_(cmd_server) * server);

/**
 * @brief Stops the server and then frees the server
 * @param server
 */
void SE_(free_server)(SE_(cmd_server) * server);

/**
 * @brief Kills any running child process, and resets the server to a ready
 * state
 * @param server
 */
void SE_(reset_server)(SE_(cmd_server) * server);

/**
 * @brief Determines if the server can transition to next_state from its current
 * state
 * @param server
 * @param next_state
 * @return True if next_state is a valid transition
 */
Bool SE_(is_valid_transition)(const SE_(cmd_server) * server,
                              SE_(cmd_server_state) next_state);

/**
 * @brief Checks for correct transition and sets the server state if correct
 * @param server
 * @param next_state
 * @return True if new state is set
 */
Bool SE_(set_server_state)(SE_(cmd_server) * server,
                           SE_(cmd_server_state) next_state);

/**
 * @brief Checks if the message is actionable given the current state of the
 * server
 * @param server
 * @param msg
 * @return True if the message can be acted upon
 */
Bool SE_(msg_can_be_handled)(const SE_(cmd_server) * server,
                             const SE_(cmd_msg) * msg);

/**
 * @brief Returns string associated with server state
 * @param state
 * @return
 */
const HChar *SE_(server_state_str)(SE_(cmd_server_state) state);

/**
 * @brief Sets all non-executable global data segments to PROT_NONE permission
 * @param server
 * @return
 */
Bool SE_(remove_global_memory_permissions)(SE_(cmd_server) * server);

/**
 * @brief Seta all non-executable global data segments to PROT_READ | PROT_WRITE
 * permission
 * @param server
 * @return
 */
Bool SE_(enable_global_memory_permissions)(SE_(cmd_server) * server);

/**
 * @brief Sets read/write permissions for allocated objects
 * @param server
 * @return
 */
Bool SE_(establish_memory_state)(SE_(cmd_server) * server);

#endif // SE_VALGRIND_SE_COMMAND_SERVER_H
