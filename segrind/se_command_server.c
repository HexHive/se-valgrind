//
// Created by derrick on 3/8/20.
//

#include "se_command_server.h"
#include "se_taint.h"

#include "pub_tool_guest.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcsignal.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_signals.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_vki.h"

#include "../coregrind/pub_core_aspacemgr.h"
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
 * @brief Writes current coverage to the commander
 * @param server
 * @return Total bytes written to the commander or 0 on error
 */
static SizeT write_coverage_to_commander(SE_(cmd_server) * server) {
  tl_assert(server);
  tl_assert(server->coverage);

  UChar *buf;

  SizeT len = SE_(Memoize_OSetWord)(server->coverage, &buf);

  /* Avoid copying the data twice */
  SE_(cmd_msg) *cmd_msg = SE_(create_cmd_msg)(SEMSG_COVERAGE, 0, NULL);
  cmd_msg->data = buf;
  cmd_msg->length = len;

  /* This frees buf */
  return write_to_commander(server, cmd_msg, True);
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
    if (SE_(set_server_state)(server, SERVER_GETTING_INIT_STATE)) {
      VG_(umsg)("Found %s at 0x%lx\n", func_name, symAvma.main);
      server->target_func_addr = symAvma.main;
      return True;
    }
  }

  server->target_func_addr = 0;
  return False;
}

/**
 * @brief Fuzzes the region specified
 * @param seed
 * @param start
 * @param end
 */
static void fuzz_region(UInt *seed, Addr start, Addr end) {
  tl_assert(start <= end);

  /* TODO: Implement a better fuzzing strategy */
  //  VG_(umsg)("Fuzzing [%p - %p]\n", (void *)start, (void *)end);
  VG_(memset)((void *)start, VG_(random)(seed), end - start);
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

  server->current_io_vec->random_seed = SE_(seed);
  server->needs_coverage = True;

  /* Fuzz input pointers */
  UInt size =
      VG_(sizeRangeMap)(server->current_io_vec->initial_state.address_state);
  Bool in_obj = False;
  for (Word i = 0; i < size; i++) {
    UWord key_min, key_max, val;
    VG_(indexRangeMap)
    (&key_min, &key_max, &val,
     server->current_io_vec->initial_state.address_state, i);

    if (val == OBJ_START_MAGIC) {
      in_obj = True;
      continue;
    } else if (val == OBJ_END_MAGIC) {
      in_obj = False;
      continue;
    }

    if (in_obj && val != ALLOCATED_SUBPTR_MAGIC) {
      fuzz_region(&SE_(seed), key_min, key_max);
    }
  }

  /* Fuzz registers, if they aren't assigned to an allocated pointer */
  Int gpr_offsets[] = SE_O_GPRS;
  for (Int i = 0; i < SE_NUM_GPRS; i++) {
    Int current_offset = gpr_offsets[i];
    RegWord reg_val = *(
        RegWord *)(&server->current_io_vec->register_state_map[current_offset]);
    if (reg_val != ALLOCATED_SUBPTR_MAGIC) {
      fuzz_region(
          &SE_(seed),
          (Addr)(
              (UChar *)&server->current_io_vec->initial_state.register_state +
              current_offset),
          (Addr)(
              (UChar *)&server->current_io_vec->initial_state.register_state +
              current_offset + sizeof(RegWord) - 1));
    }
  }

  server->current_io_vec->initial_state.register_state.VG_FRAME_PTR =
      server->initial_frame_ptr;
  server->current_io_vec->initial_state.register_state.VG_STACK_PTR =
      server->initial_stack_ptr;

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
      /* Get the initial starting state for the server */
      parent_should_fork = True;
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
  case SEMSG_COVERAGE:
    write_coverage_to_commander(server);
    msg_handled = True;
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

/**
 * @brief Allocates space for a new object and returns the address
 * @param server
 * @param size
 * @return NULL on error
 */
static Addr allocate_new_object(SE_(cmd_server) * server, SizeT size) {
  tl_assert(size > 0);

  Addr new_alloc_loc;
  //    new_alloc_loc = server->initial_frame_ptr;
  //    server->initial_frame_ptr -= size + 2;

  SysRes res =
      VG_(am_mmap_anon_float_client)(size, VKI_PROT_READ | VKI_PROT_WRITE);
  if (sr_isError(res)) {
    return 0;
  }

  new_alloc_loc = (Addr)sr_Res(res);

  /* Mark the start and end points of the object */
  VG_(bindRangeMap)
  (server->current_io_vec->initial_state.address_state, new_alloc_loc,
   new_alloc_loc, OBJ_START_MAGIC | OBJ_ALLOCATED_MAGIC);
  VG_(bindRangeMap)
  (server->current_io_vec->initial_state.address_state, new_alloc_loc + 1,
   new_alloc_loc + 1 + size, OBJ_ALLOCATED_MAGIC);
  VG_(bindRangeMap)
  (server->current_io_vec->initial_state.address_state,
   new_alloc_loc + 1 + size, new_alloc_loc + 1 + size,
   OBJ_END_MAGIC | OBJ_ALLOCATED_MAGIC);

  return new_alloc_loc;
}

/**
 * @brief Looks up if addr is in a previously allocated object
 * @param server
 * @param addr
 * @return True if the addr is in a previously allocated object
 */
static Bool lookup_obj(SE_(cmd_server) * server, Addr addr) {
  tl_assert(server);
  tl_assert(server->current_io_vec);

  UInt size =
      VG_(sizeRangeMap)(server->current_io_vec->initial_state.address_state);

  UWord min_addr, max_addr, val;
  UWord obj_start_addr = 0, obj_end_addr = 0;
  for (Int i = 0; i < size; i++) {
    VG_(indexRangeMap)
    (&min_addr, &max_addr, &val,
     server->current_io_vec->initial_state.address_state, i);

    val ^= (OBJ_ALLOCATED_MAGIC | ALLOCATED_SUBPTR_MAGIC);

    if ((val ^ OBJ_START_MAGIC) == 0) {
      obj_start_addr = min_addr;
    } else if ((val ^ OBJ_END_MAGIC) == 0) {
      obj_end_addr = max_addr;

      if (addr >= obj_start_addr && addr <= obj_end_addr) {
        return True;
      }

      obj_start_addr = 0;
      obj_end_addr = 0;
    }
  }

  return False;
}

/**
 * @brief Allocates a new object, writes the allocated address to the
 * appropriate location, and then fuzzes the new program state
 * @param server
 * @param new_alloc_msg
 * @return False on error, otherwise True
 */
static Bool handle_new_alloc(SE_(cmd_server) * server,
                             SE_(cmd_msg) * new_alloc_msg) {
  tl_assert(server);
  tl_assert(new_alloc_msg);
  tl_assert(new_alloc_msg->msg_type == SEMSG_NEW_ALLOC);
  tl_assert(server->using_fuzzed_io_vec);
  tl_assert(new_alloc_msg->data);

  Word count;
  Addr obj_loc;

  SE_(tainted_loc) tainted_loc;
  VG_(memcpy)(&count, new_alloc_msg->data, sizeof(Word));
  Word bytes_read = sizeof(Word);
  for (Word i = 0; i < count; i++) {
    VG_(memcpy)
    (&tainted_loc, (UChar *)new_alloc_msg->data + bytes_read,
     sizeof(tainted_loc));
    bytes_read += sizeof(tainted_loc);

    VG_(printf)("Received ");
    SE_(ppTaintedLocation)(&tainted_loc);

    switch (tainted_loc.type) {
    case taint_reg:
      if (tainted_loc.location.offset == VG_O_STACK_PTR ||
          tainted_loc.location.offset == VG_O_FRAME_PTR ||
          tainted_loc.location.offset == VG_O_INSTR_PTR) {
        VG_(umsg)("Invalid tainted register:\n\t");
        SE_(ppTaintedLocation(&tainted_loc));
        return False;
      }

      /* A new object needs to be allocated on the stack */
      obj_loc = allocate_new_object(server, SE_DEFAULT_ALLOC_SPACE);
      if (!obj_loc) {
        VG_(umsg)("Failed to allocate new object\n");
        return False;
      }
      VG_(printf)
      ("Setting register %d to %p\n", tainted_loc.location.offset,
       (void *)(obj_loc));
      *(Addr *)((
          (UChar *)(&server->current_io_vec->initial_state.register_state) +
          tainted_loc.location.offset)) = obj_loc;

      *(RegWord *)(&server->current_io_vec
                        ->register_state_map[tainted_loc.location.offset]) =
          ALLOCATED_SUBPTR_MAGIC;
#if defined(VGA_amd64)
      VG_(umsg)
      ("RDI = 0x%llx\n",
       server->current_io_vec->initial_state.register_state.guest_RDI);
#endif
      break;
    case taint_addr:
      if (!lookup_obj(server, tainted_loc.location.addr)) {
        obj_loc = allocate_new_object(server, SE_DEFAULT_ALLOC_SPACE);
        if (!obj_loc) {
          VG_(umsg)("Failed to allocate object\n");
          return False;
        }
        VG_(umsg)
        ("Setting %p = %p\n", (void *)tainted_loc.location.addr,
         (void *)obj_loc);
        *(Addr *)(tainted_loc.location.addr) = obj_loc;
      } else {
        /* TODO: Implement substructure pointer and object resizing */
        VG_(umsg)
        ("Could not handle tainted substructure pointer location type:\n\t");
        SE_(ppTaintedLocation)(&tainted_loc);
        return False;
      }
      break;
    default:
      VG_(umsg)("Could not handle tainted location type:\n\t");
      SE_(ppTaintedLocation)(&tainted_loc);
      return False;
    }
  }

  SE_(set_server_state)(server, SERVER_WAIT_FOR_CMD);
  fuzz_program_state(server);

  SE_(free_msg)(new_alloc_msg);
  SE_(set_server_state)(server, SERVER_WAITING_TO_EXECUTE);
  return True;
}

/**
 * @brief Consumes the coverage from the executor
 * @param server
 */
static void handle_coverage(SE_(cmd_server) * server) {
  tl_assert(server->needs_coverage);

  OSet *coverage = SE_(read_coverage)(server);
  if (!server->coverage) {
    server->coverage =
        VG_(OSetWord_Create)(VG_(malloc), SE_TOOL_ALLOC_STR, VG_(free));
  }

  UWord addr;
  while (VG_(OSetWord_Next)(coverage, &addr)) {
    if (!VG_(OSetWord_Contains)(server->coverage, addr)) {
      VG_(OSetWord_Insert)(server->coverage, addr);
    }
  }

  VG_(OSetWord_Destroy)(coverage);
}

/**
 * @brief Wait for the child process to finish executing or timeout
 * @param server
 * @return True if server should fork and execute target function again
 */
static Bool wait_for_child(SE_(cmd_server) * server) {
  tl_assert(server);
  tl_assert(server->running_pid > 0);
  tl_assert(server->current_state == SERVER_EXECUTING ||
            server->current_state == SERVER_GETTING_INIT_STATE);

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
        if (!should_fork) {
          report_error(server, "Could not handle tainted location");
        }
        /* cmd_msg is freed in handle_new_alloc */
      } else if (server->current_state == SERVER_GETTING_INIT_STATE) {
        server->attempt_count--;
        if (cmd_msg->msg_type != SEMSG_OK) {
          write_to_commander(server, cmd_msg, True);
          goto cleanup;
        } else if (cmd_msg->data == NULL ||
                   cmd_msg->length !=
                       sizeof(server->current_io_vec->initial_state
                                  .register_state)) {
          report_error(server, NULL);
          goto cleanup;
        }

        if (server->current_io_vec) {
          SE_(free_io_vec)(server->current_io_vec);
        }
        server->current_io_vec = SE_(create_io_vec)();
        VG_(memcpy)
        ((UChar *)&server->current_io_vec->initial_state.register_state,
         cmd_msg->data, cmd_msg->length);
        SE_(free_msg)(cmd_msg);
        server->initial_stack_ptr =
            server->current_io_vec->initial_state.register_state.VG_STACK_PTR;
        server->initial_frame_ptr = server->initial_stack_ptr;
        VG_(umsg)
        ("Got initial state FP = %p\n", (void *)server->initial_frame_ptr);
        report_success(server, 0, NULL);
      } else {
        if (cmd_msg->msg_type == SEMSG_OK && server->needs_coverage) {
          handle_coverage(server);
        }
        write_to_commander(server, cmd_msg, True);
      }
    }
    goto cleanup;
  } else if ((fds[0].revents & VKI_POLLHUP) == VKI_POLLHUP) {
    VG_(umsg)("Executor Hung up\n");
    report_error(server, NULL);
  }

cleanup:
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

  VG_(memset)(cmd_server, 0, sizeof(SE_(cmd_server)));
  SE_(reset_server)(cmd_server);
  cmd_server->commander_r_fd = commander_r_fd;
  cmd_server->commander_w_fd = commander_w_fd;
  cmd_server->current_state = SERVER_WAIT_FOR_START;
  cmd_server->initial_frame_ptr = -1;
  cmd_server->initial_stack_ptr = -1;

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
    if (server->current_state != SERVER_GETTING_INIT_STATE)
      if (!SE_(set_server_state)(server, SERVER_EXECUTING)) {
        VG_(umsg)
        ("Invalid server transition: %s -> SERVER_EXECUTING\n",
         SE_(server_state_str)(server->current_state));
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
        } else {
          break;
        }
      }
    }
  }

exit:
  server->attempt_count = 0;
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
    return (next_state == SERVER_GETTING_INIT_STATE);
  case SERVER_GETTING_INIT_STATE:
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
  case SERVER_INVALID:
    return True;
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
  case SERVER_GETTING_INIT_STATE:
    return "SERVER_GETTING_INIT_STATE";
  default:
    VG_(umsg)("Unknown state: %u\n", state);
    return "UNKNOWN_STATE";
  }
}

void SE_(stop_server)(SE_(cmd_server) * server) {
  tl_assert(server);

  SE_(reset_server)(server);
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
  server->needs_coverage = False;

  if (server->coverage) {
    VG_(OSetWord_Destroy)(server->coverage);
    server->coverage = NULL;
  }

  if (server->current_io_vec) {
    SE_(free_io_vec)(server->current_io_vec);
    server->current_io_vec = NULL;
  }

  SE_(set_server_state)(server, SERVER_WAIT_FOR_CMD);
}

OSet *SE_(read_coverage)(SE_(cmd_server) * server) {
  SE_(cmd_msg) *msg = read_from_executor(server);
  tl_assert(msg);
  tl_assert(msg->msg_type == SEMSG_COVERAGE);
  tl_assert(msg->length > 0);

  SizeT bytes_read = 0;

  OSet *result =
      VG_(OSetWord_Create)(VG_(malloc), SE_TOOL_ALLOC_STR, VG_(free));
  Word count;
  VG_(memcpy)(&count, msg->data, sizeof(count));
  bytes_read += sizeof(count);
  for (Word i = 0; i < count; i++) {
    Word addr;
    VG_(memcpy)(&addr, (UChar *)msg->data + bytes_read, sizeof(addr));
    bytes_read += sizeof(addr);

    if (!VG_(OSetWord_Contains)(result, addr)) {
      VG_(OSetWord_Insert)(result, addr);
    }
  }

  SE_(free_msg)(msg);

  return result;
}