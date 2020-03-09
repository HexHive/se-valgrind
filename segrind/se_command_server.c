//
// Created by derrick on 3/8/20.
//

#include "se_command_server.h"
#include "se.h"

#include "pub_tool_libcproc.h"
#include "pub_tool_libcsignal.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_vki.h"

#include "../coregrind/pub_core_debuginfo.h"

#include <sys/wait.h>

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

  SizeT bytes_written = SE_(write_msg_to_fd)(server->commander_w_fd, msg);
  if (bytes_written <= 0) {
    bytes_written = 0;
    VG_(umsg)
    ("Failed to write %s message to commander\n",
     SE_(msg_type_str(msg->msg_type)));
  }

  if (free_msg) {
    SE_(free_msg)(msg);
  }

  return bytes_written;
}

/**
 * @brief Reads a single command message from the read command pipe
 * @param server
 * @return Command message or NULL on error;
 */
static SE_(cmd_msg) * read_from_commander(SE_(cmd_server) * server) {
  SE_(cmd_msg_t) msg_type;
  if (VG_(read)(server->commander_r_fd, &msg_type, sizeof(msg_type)) <= 0) {
    return NULL;
  }

  SizeT len;
  if (VG_(read)(server->commander_r_fd, &len, sizeof(len)) <= 0) {
    return NULL;
  }

  char *buf = NULL;
  if (len > 0) {
    buf = VG_(malloc)(SE_MSG_MALLOC_TYPE, len);
    tl_assert(buf);
    if (VG_(read)(server->commander_r_fd, buf, len) <= 0) {
      VG_(free)(buf);
      return NULL;
    }
  }

  SE_(cmd_msg) *result = SE_(create_cmd_msg)(msg_type, len, buf);
  VG_(free)(buf);
  return result;
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
}

static void report_success(SE_(cmd_server) * server, SizeT len, void *data) {
  SE_(cmd_msg) *cmdmsg = SE_(create_cmd_msg)(SEMSG_OK, len, data);
  write_to_commander(server, cmdmsg, True);
}

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
  if (VG_(lookup_symbol_SLOW)(VG_(current_DiEpoch()), "*", func_name,
                              &symAvma)) {
    server->target_func_addr = symAvma.main;
    return True;
  } else {
    server->target_func_addr = 0;
    return False;
  }
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
    /* TODO: Implement me when IOVecs are ported */
    break;
  case SEMSG_EXECUTE:
    msg_handled = SE_(set_server_state)(server, SERVER_EXECUTING);
    /* We want to fork a new process to actually execute the target code */
    parent_should_fork = True;
    break;
  case SEMSG_SET_CTX:
    /* TODO: Implement me when IOVecs are ported */
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

static void wait_for_child(SE_(cmd_server) * server) {
  tl_assert(server);
  tl_assert(server->running_pid > 0);

  UInt initial_time = VG_(read_millisecond_timer)();
  UInt current_time = initial_time;
  const HChar *error_msg = "Time expired";
  while (current_time - initial_time < SE_(MaxDuration)) {
    Int status;
    Int wait_status;
    wait_status = VG_(waitpid)(server->running_pid, &status, VKI_WNOHANG);
    if (wait_status < 0) {
      error_msg = "Waitpid failed";
      break;
    } else if (wait_status == 0) {
      current_time = VG_(read_millisecond_timer)();
    } else {
      if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        server->running_pid = -1;
      } else {
        error_msg = "Error executing target";
      }
      break;
    }
  }

  if (server->running_pid > 0) {
    VG_(kill)(server->running_pid, VKI_SIGKILL);
    server->running_pid = -1;
    report_error(server, error_msg);
  }
}

SE_(cmd_server) * SE_(make_server)(Int commander_in_fd, Int commander_out_fd) {
  tl_assert(commander_in_fd > 0);
  tl_assert(commander_out_fd > 0);

  SE_(cmd_server) *cmd_server = (SE_(cmd_server) *)VG_(malloc)(
      "SE_(cmd_server)", sizeof(SE_(cmd_server)));
  tl_assert(cmd_server);

  cmd_server->commander_r_fd = commander_in_fd;
  cmd_server->commander_w_fd = commander_out_fd;
  cmd_server->current_state = SERVER_WAIT_FOR_START;
  cmd_server->running_pid = -1;
  cmd_server->target_func_addr = (Addr)NULL;

  return cmd_server;
}

void SE_(start_server)(SE_(cmd_server) * server) {
  tl_assert(server);
  tl_assert(server->current_state == SERVER_WAIT_FOR_START);

  VG_(umsg)("Starting Command Server");
  SE_(cmd_msg) *ready_msg = SE_(create_cmd_msg)(SEMSG_READY, 0, NULL);
  write_to_commander(server, ready_msg, True);

  SE_(set_server_state)(server, SERVER_WAIT_FOR_TARGET);

  do {
    struct vki_pollfd fds[1];
    fds[0].fd = server->commander_r_fd;
    fds[0].events = VKI_POLLIN;
    fds[0].revents = 0;

    if (sr_isError(
            VG_(poll)(fds, sizeof(fds) / sizeof(struct vki_pollfd), -1))) {
      VG_(tool_panic)("VG_(poll) failed!");
    }

    if (fds[0].revents & VKI_POLLIN) {
      if (handle_command(server)) {
        Int pid = VG_(fork)();
        if (pid < 0) {
          report_error(server, "Failed to fork child process");
        } else if (pid == 0) {
          /* Child process exits and starts executing target code */
          return;
        } else {
          server->running_pid = pid;
          wait_for_child(server);
        }
      }
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
    tl_assert(0);
  }
}

void SE_(stop_server)(SE_(cmd_server) * server) {
  tl_assert(server);

  if (server->running_pid > 0) {
    VG_(kill)(server->running_pid, VKI_SIGKILL);
  }

  VG_(close)(server->commander_r_fd);
  VG_(close)(server->commander_w_fd);

  server->running_pid = -1;
  server->current_state = SERVER_EXIT;
}

void SE_(free_server)(SE_(cmd_server) * server) {
  SE_(stop_server)(server);
  VG_(free)(server);
}
