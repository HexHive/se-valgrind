//
// Created by derrick on 3/8/20.
//

#include "se_command_server.h"

#include "pub_tool_guest.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcsignal.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_signals.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_vki.h"

#include "../coregrind/pub_core_debuginfo.h"

#include <sys/wait.h>

SE_(io_vec) * SE_(current_io_vec) = NULL;

/**
 * @brief Write message to commander pipe
 * @param server
 * @param msg
 * @return Total bytes written or 0 on error
 */
static SizeT write_to_commander(SE_(cmd_server) * server, SE_(cmd_msg) * msg,
                                Bool free_msg) {
  tl_assert(server);
  tl_assert(msg);

  SizeT bytes_written =
      SE_(write_msg_to_fd)(server->commander_w_fd, msg, free_msg);
  if (bytes_written <= 0) {
    VG_(umsg)
    ("Failed to write %s message to commander: %lu\n",
     SE_(msg_type_str)(msg->msg_type), bytes_written);
    bytes_written = 0;
  }

  return bytes_written;
}

/**
 * @brief Reads a single command message from the read command pipe
 * @param server
 * @return Command message or NULL on error
 */
static SE_(cmd_msg) * read_from_commander(SE_(cmd_server) * server) {
  tl_assert(server);

  return SE_(read_msg_from_fd)(server->commander_r_fd);
}

/**
 * @brief Reads a single message from the executor pipe
 * @param server
 * @return Command message or NULL on error
 */
static SE_(cmd_msg) * read_from_executor(SE_(cmd_server) * server) {
  tl_assert(server);
  tl_assert(server->running_pid > 0);

  return SE_(read_msg_from_fd)(server->executor_pipe[0]);
}

/**
 * @brief Writes an error message to the command pipe
 * @param server
 * @param msg - Message to write
 */
static void report_error(SE_(cmd_server) * server, const HChar *msg) {
  SizeT msg_len = 0;
  if (msg) {
    msg_len = VG_(strlen)(msg);
  }

  SE_(cmd_msg) *cmdmsg = SE_(create_cmd_msg)(SEMSG_FAIL, msg_len, msg);
  write_to_commander(server, cmdmsg, True);

  SE_(set_server_state)(server, SERVER_REPORT_ERROR);
}

/**
 * @brief Writes timeout msg to command pipe
 * @param server
 */
static void report_timeout(SE_(cmd_server) * server) {
  SE_(cmd_msg) *cmdmsg = SE_(create_cmd_msg)(SEMSG_TOO_MANY_INS, 0, NULL);
  write_to_commander(server, cmdmsg, True);
  SE_(set_server_state)(server, SERVER_REPORT_ERROR);
}

/**
 * @brief Sends a success message to the commander process
 * @param server
 * @param len - length of data
 * @param data - data to include with success message
 */
static void report_success(SE_(cmd_server) * server, SizeT len, void *data) {
  SE_(cmd_msg) *cmdmsg = SE_(create_cmd_msg)(SEMSG_OK, len, data);
  write_to_commander(server, cmdmsg, True);
}

/**
 * @brief Sends ACK to commander process
 * @param server
 */
static void send_ack_to_commander(SE_(cmd_server) * server) {
  write_to_commander(server, SE_(create_cmd_msg)(SEMSG_ACK, 0, NULL), True);
}

/**
 * @brief Looks up symbol name, and sets server->target_func_addr if found, or 0
 * if not found
 * @param msg
 * @param server
 * @return True if address is found
 */
static Bool handle_set_target_cmd(SE_(cmd_msg) * msg,
                                  SE_(cmd_server) * server) {
  tl_assert(msg);
  tl_assert(msg->msg_type == SEMSG_SET_TGT);
  tl_assert(server);

  HChar *func_name = (HChar *)msg->data;
  tl_assert(VG_(strlen)(func_name) > 0);

  SymAVMAs symAvma;
  VG_(umsg)("Looking for function %s\n", func_name);
  if (VG_(lookup_symbol_SLOW)(VG_(current_DiEpoch()), "*", func_name,
                              &symAvma)) {
    if (SE_(set_server_state)(server, SERVER_WAIT_FOR_CMD)) {
      VG_(umsg)("Found %s at 0x%lx\n", func_name, symAvma.main);
      server->target_func_addr = symAvma.main;
      return True;
    }
  }

  server->target_func_addr = 0;
  return False;
}

/**
 * @brief Fuzzes and sets the guest program state
 * @param server
 * @return True if program state was successfully fuzzed
 */
static Bool fuzz_program_state(SE_(cmd_server) * server) {
  tl_assert(server);

  if (!SE_(set_server_state)(server, SERVER_FUZZING)) {
    return False;
  }

  if (SE_(current_io_vec)) {
    SE_(free_io_vec)(SE_(current_io_vec));
  }

  SE_(current_io_vec) = SE_(create_io_vec)();

  VG_(get_shadow_regs_area)
  (server->executor_tid, (UChar *)&SE_(current_io_vec)->initial_state, 0, 0,
   sizeof(SE_(current_io_vec)->initial_state));
#if defined(VGA_amd64)
  VG_(umsg)
  ("Initial RDI = 0x%llx\n", SE_(current_io_vec)->initial_state.guest_RDI);
  SE_(current_io_vec)->initial_state.guest_RDI = VG_(random)(&SE_(seed));
  VG_(umsg)
  ("Setting RDI = 0x%llx\n", SE_(current_io_vec)->initial_state.guest_RDI);
  SE_(current_io_vec)->initial_state.guest_RAX = 0;
#endif

  return SE_(set_server_state)(server, SERVER_WAITING_TO_EXECUTE);
}

/**
 * @brief Reads from the command pipe and handles the command
 * @param server
 * @return True if parent should fork because an Execute command was issued
 */
static Bool handle_command(SE_(cmd_server) * server) {
  SE_(cmd_msg) *cmd_msg = read_from_commander(server);
  if (cmd_msg == NULL) {
    report_error(server, "Failed to read message");
    return False;
  }
  send_ack_to_commander(server);

  Bool parent_should_fork = False;
  Bool msg_handled = False;
  switch (cmd_msg->msg_type) {
  case SEMSG_SET_TGT:
    msg_handled = handle_set_target_cmd(cmd_msg, server);
    if (msg_handled) {
      report_success(server, 0, NULL);
    }
    break;
  case SEMSG_EXIT:
    SE_(stop_server)(server);
    msg_handled = True;
    break;
  case SEMSG_FUZZ:
    msg_handled = fuzz_program_state(server);
    if (msg_handled) {
      server->using_fuzzed_io_vec = True;
      server->using_existing_io_vec = False;
      report_success(server, 0, NULL);
    }
    break;
  case SEMSG_EXECUTE:
    msg_handled = SE_(set_server_state)(server, SERVER_EXECUTING);
    if (!msg_handled) {
      VG_(umsg)
      ("Could not set execution state from %s\n",
       SE_(server_state_str)(server->current_state));
    } else {
      VG_(umsg)
      ("Server state set to %s\n",
       SE_(server_state_str)(server->current_state));
    }
    /* We want to fork a new process to actually execute the target code */
    parent_should_fork = True;
    break;
  case SEMSG_SET_CTX:
    /* TODO: Implement me when IOVecs are ported */
    server->using_existing_io_vec = True;
    server->using_fuzzed_io_vec = False;
    break;
  default:
    msg_handled = True;
    break;
  }

  SE_(free_msg)(cmd_msg);
  if (!msg_handled) {
    report_error(server, NULL);
    parent_should_fork = False;
  }

  return parent_should_fork;
}

static Bool handle_new_alloc(SE_(cmd_server) * server,
                             SE_(cmd_msg) * new_alloc_msg) {
  tl_assert(server);
  tl_assert(new_alloc_msg);
  tl_assert(new_alloc_msg->msg_type == SEMSG_NEW_ALLOC);
  tl_assert(server->using_fuzzed_io_vec);

  // TODO: Implement fetching of new alloc

  SE_(set_server_state)(server, SERVER_WAIT_FOR_CMD);
  fuzz_program_state(server);

  SE_(free_msg)(new_alloc_msg);
  SE_(set_server_state)(server, SERVER_WAITING_TO_EXECUTE);
  return True;
}

/**
 * @brief Wait for the child process to finish executing or timeout
 * @param server
 * @return True if server should fork and execute target function again
 */
static Bool wait_for_child(SE_(cmd_server) * server) {
  tl_assert(server);
  tl_assert(server->running_pid > 0);
  tl_assert(server->current_state == SERVER_EXECUTING);

  Int status;
  Int wait_result;
  Bool should_fork = False;

  struct vki_pollfd fds[1];
  fds[0].fd = server->executor_pipe[0];
  fds[0].events = VKI_POLLIN | VKI_POLLHUP | VKI_POLLPRI;
  VG_(umsg)
  ("Waiting for child process %d for %u ms\n", server->running_pid,
   SE_(MaxDuration));
  fds[0].revents = 0;
  SysRes result =
      VG_(poll)(fds, sizeof(fds) / sizeof(struct vki_pollfd), SE_(MaxDuration));
  if (sr_Res(result) == 0) {
    if (sr_Err(result)) {
      VG_(umsg)("Poll failed\n");
      report_error(server, "Executor poll failed");
    } else {
      VG_(umsg)("Poll timed out\n");
      report_timeout(server);
    }

    goto cleanup;
  }

  if (((fds[0].revents & VKI_POLLIN) == VKI_POLLIN) ||
      ((fds[0].revents & VKI_POLLPRI) == VKI_POLLPRI)) {
    SE_(cmd_msg) *cmd_msg = read_from_executor(server);
    if (cmd_msg == NULL) {
      VG_(umsg)("Reading from executor failed\n");
      report_error(server, "Error reading executor pipe");
    } else {
      VG_(umsg)
      ("Got %s message from executor\n", SE_(msg_type_str)(cmd_msg->msg_type));
      if (server->using_fuzzed_io_vec && cmd_msg->msg_type == SEMSG_NEW_ALLOC) {
        should_fork = handle_new_alloc(server, cmd_msg);
      } else {
        write_to_commander(server, cmd_msg, True);
      }
    }
    goto cleanup;
  } else if ((fds[0].revents & VKI_POLLHUP) == VKI_POLLHUP) {
    VG_(umsg)("Executor Hung up\n");
  }
  report_error(server, NULL);

cleanup:
  VG_(umsg)("Cleaning up\n");
  wait_result = VG_(waitpid)(server->running_pid, &status, VKI_WNOHANG);
  if (wait_result < 0 || (!WIFEXITED(status) && !WIFSIGNALED(status))) {
    VG_(kill)(server->running_pid, VKI_SIGKILL);
  }

  server->running_pid = -1;
  VG_(close)(server->executor_pipe[0]);
  if (!should_fork) {
    SE_(set_server_state)(server, SERVER_WAIT_FOR_CMD);
  }

  return should_fork;
}

SE_(cmd_server) * SE_(make_server)(Int commander_r_fd, Int commander_w_fd) {
  tl_assert(commander_w_fd > 0);
  tl_assert(commander_r_fd > 0);

  SE_(cmd_server) *cmd_server = (SE_(cmd_server) *)VG_(malloc)(
      "SE_(cmd_server)", sizeof(SE_(cmd_server)));
  tl_assert(cmd_server);
  VG_(umsg)("Command Server created!\n");

  cmd_server->current_state = SERVER_WAIT_FOR_CMD;
  SE_(reset_server)(cmd_server);
  cmd_server->commander_r_fd = commander_r_fd;
  cmd_server->commander_w_fd = commander_w_fd;
  cmd_server->current_state = SERVER_WAIT_FOR_START;

  return cmd_server;
}

/**
 * @brief Forks the current process and waits for the child to finish
 * @param server
 * @return True if the calling function should return
 */
static Bool SE_(fork_and_execute)(SE_(cmd_server) * server) {
  Int pid;

  while (server->attempt_count <= SE_(MaxAttempts)) {
    if (!SE_(set_server_state)(server, SERVER_EXECUTING)) {
      report_error(server, "Invalid server state");
      goto exit;
    }
    VG_(umsg)
    ("Server forking %u with status %s\n", server->attempt_count,
     SE_(server_state_str)(server->current_state));

    if (VG_(pipe)(server->executor_pipe) < 0) {
      report_error(server, "Pipe failed");
      goto exit;
    }

    pid = VG_(fork)();
    if (pid < 0) {
      VG_(close)(server->executor_pipe[0]);
      VG_(close)(server->executor_pipe[1]);
      server->executor_pipe[0] = server->executor_pipe[1] = -1;

      report_error(server, "Failed to fork child process");
      goto exit;
    } else {
      if (pid == 0) {
        VG_(close)(server->executor_pipe[0]);
        VG_(close)(server->commander_r_fd);
        VG_(close)(server->commander_w_fd);

        /* Child process exits and starts executing target code */
        return True;
      } else {
        server->running_pid = pid;
        server->attempt_count++;
        VG_(close)(server->executor_pipe[1]);
        if (wait_for_child(server)) {
          if (server->attempt_count >= SE_(MaxAttempts)) {
            write_to_commander(
                server, SE_(create_cmd_msg)(SEMSG_TOO_MANY_ATTEMPTS, 0, NULL),
                True);
            break;
          }
        }
      }
    }
  }

exit:
  SE_(set_server_state)(server, SERVER_WAIT_FOR_CMD);
  return False;
}

void SE_(start_server)(SE_(cmd_server) * server, ThreadId executor_tid) {
  tl_assert(server);
  tl_assert(server->current_state == SERVER_WAIT_FOR_START);
  tl_assert(executor_tid != VG_INVALID_THREADID);
  tl_assert(executor_tid != VG_(get_running_tid)());

  server->executor_tid = executor_tid;

  SymAVMAs symAvma;
  VG_(umsg)("Looking for function main\n");
  if (VG_(lookup_symbol_SLOW)(VG_(current_DiEpoch()), "*", "main", &symAvma)) {
    VG_(umsg)("Found main at 0x%lx\n", symAvma.main);
    if (SE_(user_main) > 0 && SE_(user_main) != symAvma.main) {
      VG_(umsg)
      ("WARNING: User specified main (0x%lx) is different from Valgrind found "
       "main (0x%lx)! Using user specified main...",
       SE_(user_main), symAvma.main);
      server->main_addr = SE_(user_main);
    } else {
      server->main_addr = symAvma.main;
    }
  }

  SE_(set_server_state)(server, SERVER_START);

  SE_(cmd_msg) *ready_msg = SE_(create_cmd_msg)(SEMSG_READY, 0, NULL);
  if (write_to_commander(server, ready_msg, True) == 0) {
    VG_(tool_panic)("Could not write ready message to pipe\n");
  }

  SE_(set_server_state)(server, SERVER_WAIT_FOR_TARGET);

  do {
    struct vki_pollfd fds[1];
    fds[0].fd = server->commander_r_fd;
    fds[0].events = VKI_POLLIN | VKI_POLLHUP | VKI_POLLPRI;
    fds[0].revents = 0;

    VG_(umsg)
    ("Current server status: %s\n",
     SE_(server_state_str)(server->current_state));
    if (sr_isError(
            VG_(poll)(fds, sizeof(fds) / sizeof(struct vki_pollfd), -1))) {
      VG_(tool_panic)("VG_(poll) failed!\n");
    }

    if (((fds[0].revents & VKI_POLLIN) == VKI_POLLIN) ||
        ((fds[0].revents & VKI_POLLPRI) == VKI_POLLPRI)) {
      if (handle_command(server)) {
        if (SE_(fork_and_execute)(server)) {
          return;
        }
      } else {
        VG_(umsg)
        ("Server NOT forking with status %s\n",
         SE_(server_state_str)(server->current_state));
      }
    } else if ((fds[0].revents & VKI_POLLHUP) == VKI_POLLHUP) {
      VG_(umsg)("Server write command pipe closed...\n");
      return;
    }
  } while (server->current_state != SERVER_EXIT);
}

Bool SE_(is_valid_transition)(const SE_(cmd_server) * server,
                              SE_(cmd_server_state) next_state) {
  tl_assert(server);

  if (next_state == server->current_state || next_state == SERVER_EXIT) {
    return True;
  }

  switch (server->current_state) {
  case SERVER_WAIT_FOR_START:
    return (next_state == SERVER_START);
  case SERVER_START:
    return (next_state == SERVER_WAIT_FOR_TARGET);
  case SERVER_WAIT_FOR_TARGET:
    return (next_state == SERVER_WAIT_FOR_CMD);
  case SERVER_WAIT_FOR_CMD:
    return (next_state == SERVER_FUZZING || next_state == SERVER_SETTING_CTX);
  case SERVER_FUZZING:
  case SERVER_SETTING_CTX:
    return (next_state == SERVER_WAIT_FOR_CMD ||
            next_state == SERVER_WAITING_TO_EXECUTE);
  case SERVER_WAITING_TO_EXECUTE:
    return (next_state == SERVER_WAIT_FOR_CMD ||
            next_state == SERVER_EXECUTING);
  case SERVER_EXECUTING:
    return (next_state == SERVER_WAIT_FOR_CMD ||
            next_state == SERVER_REPORT_ERROR);
  case SERVER_REPORT_ERROR:
    return (next_state == SERVER_WAIT_FOR_CMD);
  default:
    return False;
  }
}

Bool SE_(set_server_state)(SE_(cmd_server) * server,
                           SE_(cmd_server_state) next_state) {
  Bool res = SE_(is_valid_transition)(server, next_state);
  if (res) {
    server->current_state = next_state;
  } else {
    VG_(umsg)
    ("Invalid transition: %s -> %s\n",
     SE_(server_state_str)(server->current_state),
     SE_(server_state_str)(next_state));
  }

  return res;
}

Bool SE_(msg_can_be_handled)(const SE_(cmd_server) * server,
                             const SE_(cmd_msg) * msg) {
  tl_assert(server);
  tl_assert(msg);

  /* We always want to be able to exit */
  if (msg->msg_type == SEMSG_EXIT) {
    return True;
  }

  switch (server->current_state) {
  case SERVER_WAIT_FOR_START:
  case SERVER_WAIT_FOR_TARGET:
    return (msg->msg_type == SEMSG_SET_TGT ||
            msg->msg_type == SEMSG_SET_SO_TGT);
  case SERVER_WAIT_FOR_CMD:
    return (msg->msg_type == SEMSG_SET_TGT ||
            msg->msg_type == SEMSG_SET_SO_TGT || msg->msg_type == SEMSG_FUZZ ||
            msg->msg_type == SEMSG_SET_CTX || msg->msg_type == SEMSG_RESET);
  case SERVER_FUZZING:
    return (msg->msg_type == SEMSG_RESET);
  case SERVER_EXECUTING:
    return (msg->msg_type == SEMSG_RESET);
  case SERVER_REPORT_ERROR:
    return (msg->msg_type == SEMSG_RESET);
  case SERVER_SETTING_CTX:
    return (msg->msg_type == SEMSG_RESET);
  case SERVER_WAITING_TO_EXECUTE:
    return (msg->msg_type == SEMSG_RESET || msg->msg_type == SEMSG_EXECUTE);
  default:
    return False;
  }
}

const HChar *SE_(server_state_str)(SE_(cmd_server_state) state) {
  switch (state) {
  case SERVER_INVALID:
    return "SERVER_INVALID";
  case SERVER_WAIT_FOR_START:
    return "SERVER_WAIT_FOR_START";
  case SERVER_START:
    return "SERVER_START";
  case SERVER_WAIT_FOR_TARGET:
    return "SERVER_WAIT_FOR_TARGET";
  case SERVER_WAIT_FOR_CMD:
    return "SERVER_WAIT_FOR_CMD";
  case SERVER_FUZZING:
    return "SERVER_FUZZING";
  case SERVER_EXECUTING:
    return "SERVER_EXECUTING";
  case SERVER_EXIT:
    return "SERVER_EXIT";
  case SERVER_REPORT_ERROR:
    return "SERVER_REPORT_ERROR";
  case SERVER_SETTING_CTX:
    return "SERVER_SETTING_CTX";
  case SERVER_WAITING_TO_EXECUTE:
    return "SERVER_WAITING_TO_EXECUTE";
  default:
    VG_(umsg)("Unknown state: %u\n", state);
    return "UNKNOWN_STATE";
  }
}

void SE_(stop_server)(SE_(cmd_server) * server) {
  tl_assert(server);

  if (server->running_pid > 0) {
    VG_(kill)(server->running_pid, VKI_SIGKILL);
  }

  VG_(close)(server->commander_r_fd);
  VG_(close)(server->commander_w_fd);

  VG_(close)(server->executor_pipe[0]);
  VG_(close)(server->executor_pipe[1]);

  server->running_pid = -1;
  server->current_state = SERVER_EXIT;
}

void SE_(free_server)(SE_(cmd_server) * server) {
  SE_(stop_server)(server);
  VG_(free)(server);
}

void SE_(reset_server)(SE_(cmd_server) * server) {
  if (server->running_pid > 0) {
    VG_(kill)(server->running_pid, VKI_SIGKILL);
  }

  server->running_pid = -1;
  if (server->executor_pipe[0] > 0) {
    VG_(close)(server->executor_pipe[0]);
    server->executor_pipe[0] = -1;
  }
  if (server->executor_pipe[1] > 0) {
    VG_(close)(server->executor_pipe[1]);
    server->executor_pipe[1] = -1;
  }
  server->target_func_addr = (Addr)NULL;
  server->using_fuzzed_io_vec = False;
  server->using_existing_io_vec = False;
  server->attempt_count = 0;

  SE_(set_server_state)(server, SERVER_WAIT_FOR_CMD);
}
