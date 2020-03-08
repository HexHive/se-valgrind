//
// Created by derrick on 3/8/20.
//

#include "se_command_server.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_vki.h"

/**
 * @brief Write message to commander pipe
 * @param server
 * @param msg
 * @return Total bytes written or 0 on error
 */
static SizeT SE_(write_to_commander)(SE_(cmd_server) * server,
                                     const SE_(cmd_msg) * msg, Bool free_msg) {
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

SE_(cmd_server) * SE_(make_server)(const HChar *commander_in_path,
                                   const HChar *commander_out_path) {
  SE_(cmd_server) *cmd_server = (SE_(cmd_server) *)VG_(malloc)(
      "SE_(cmd_server)", sizeof(SE_(cmd_server)));
  if (!cmd_server) {
    return (SE_(cmd_server *)) - 1;
  }

  cmd_server->commander_r_fd = VG_(fd_open)(commander_in_path, VKI_O_RDONLY, 0);
  if (cmd_server->commander_r_fd < 0) {
    VG_(umsg)("Server failed to open %s\n", commander_in_path);
    VG_(free)(cmd_server);
    return (SE_(cmd_server *)) - 1;
  }

  cmd_server->commander_w_fd =
      VG_(fd_open)(commander_out_path, VKI_O_WRONLY, 0);
  if (cmd_server->commander_w_fd < 0) {
    VG_(umsg)("Server failed to open %s\n", commander_in_path);
    VG_(free)(cmd_server);
    return (SE_(cmd_server *)) - 1;
  }
  cmd_server->current_state = SERVER_WAIT_FOR_START;

  return cmd_server;
}

void SE_(start_server)(SE_(cmd_server) * server) {
  tl_assert(server);
  tl_assert(server->current_state == SERVER_WAIT_FOR_START);

  VG_(umsg)("Starting Command Server");
  SE_(cmd_msg) *ready_msg = SE_(create_cmd_msg)(SEMSG_READY, 0, NULL);
  SE_(write_to_commander)(server, ready_msg, True);
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
