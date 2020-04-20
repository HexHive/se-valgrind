//
// Created by derrick on 3/8/20.
//

#include "se_command_server.h"
#include "se_fuzz.h"
#include "se_taint.h"
#include "se_utils.h"

#include "pub_tool_addrinfo.h"
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

  SE_(memoized_object) obj;

  SE_(Memoize_OSetWord)(server->coverage, &obj);

  /* Avoid copying the data twice */
  SE_(cmd_msg) *cmd_msg = SE_(create_cmd_msg)(SEMSG_COVERAGE, 0, NULL);
  cmd_msg->data = obj.buf;
  cmd_msg->length = obj.len;

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
  SE_(cmd_msg) *cmdmsg = SE_(create_cmd_msg)(SEMSG_TIMEOUT, 0, NULL);
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

  Addr *func_addr = (Addr *)msg->data;
  Addr final_addr = 0;
  const HChar *func_name;
  VG_(umsg)("Looking for function at 0x%lx\n", *func_addr);
  final_addr = CLIENT_CODE_LOAD_ADDR + *func_addr;

  VG_(get_fnname)
  (VG_(current_DiEpoch)(), final_addr, &func_name);
  if (VG_(strlen)(func_name) == 0) {
    final_addr = *func_addr;
    VG_(get_fnname)
    (VG_(current_DiEpoch)(), final_addr, &func_name);
  }

  if (VG_(strlen)(func_name) > 0 &&
      SE_(set_server_state)(server, SERVER_GETTING_INIT_STATE)) {
    VG_(umsg)("Found %s at 0x%lx\n", func_name, final_addr);
    server->target_func_addr = final_addr;
    if (server->current_io_vec) {
      SE_(free_io_vec)(server->current_io_vec);
    }
    server->current_io_vec = SE_(create_io_vec)();

    return True;
  }

  VG_(umsg)("Could not find function at 0x%lx\n", *func_addr);
  server->target_func_addr = 0;
  return False;
}

/**
 * @brief Sets allocated areas to random values based on the seed
 * @param io_vec
 * @param seed
 */
static void fuzz_input_pointers(SE_(io_vec) * io_vec, UInt *seed) {
  tl_assert(io_vec);
  tl_assert(seed);

  UInt size = VG_(sizeRangeMap)(io_vec->initial_state.address_state);
  Addr obj_start = 0;
  //  VG_(umsg)("Fuzzing allocated areas with seed %u\n", *seed);
  for (Word i = 0; i < size; i++) {
    UWord key_min, key_max, val;
    VG_(indexRangeMap)
    (&key_min, &key_max, &val, io_vec->initial_state.address_state, i);

    //        VG_(umsg)("\t[0x%lx - 0x%lx] = %lu %d\n", key_min, key_max, val,
    //        val & OBJ_END_MAGIC);

    if (val & OBJ_START_MAGIC) {
      obj_start = (Addr)key_min;
    }

    if (val & OBJ_END_MAGIC) {
      /* Establish a randomize base for accurate recreation later */
      UChar *curr = (UChar *)obj_start;
      for (; curr <= (UChar *)key_max; curr++) {
        *curr = (UChar)VG_(random)(seed);
      }
      SE_(fuzz_region)(seed, obj_start, (Addr)key_max);
      continue;
    }
  }

  for (UInt i = 0;
       i < VG_(sizeRangeMap)(io_vec->initial_state.pointer_member_locations);
       i++) {
    UWord addr_min, addr_max, val;
    VG_(indexRangeMap)
    (&addr_min, &addr_max, &val, io_vec->initial_state.pointer_member_locations,
     i);
    if (val > 0) {
      tl_assert(sizeof(val) >= (addr_max - addr_min));
      VG_(memcpy)((void *)addr_min, &val, addr_max - addr_min + 1);
      //      VG_(umsg)
      //      ("Set %p to 0x%0lx and should be 0x%lx\n", (void *)addr_min,
      //       *(Addr *)(addr_min), val);
    }
  }
}

/**
 * @brief Randomly sets the GPRs to a value based on the seed
 * @param io_vec
 * @param seed
 */
static void fuzz_registers(SE_(io_vec) * io_vec, UInt *seed) {
  tl_assert(io_vec);
  tl_assert(seed);

  //  VG_(umsg)("Fuzzing registers\n");
  /* Fuzz registers, if they aren't assigned to an allocated pointer */
  Int gpr_offsets[] = SE_O_GPRS;
  for (Int i = 0; i < SE_NUM_GPRS; i++) {
    Int current_offset = gpr_offsets[i];
    SE_(register_value) *reg_val = NULL;
    for (Word j = 0; i < VG_(sizeXA)(io_vec->initial_state.register_state);
         j++) {
      SE_(register_value) *tmp =
          VG_(indexXA)(io_vec->initial_state.register_state, j);
      if (tmp->guest_state_offset == current_offset) {
        reg_val = tmp;
        break;
      }
    }
    if (!reg_val) {
      SE_(register_value) new_val;
      new_val.guest_state_offset = current_offset;
      new_val.is_ptr = False;
      new_val.value = 0;
      VG_(addToXA)(io_vec->initial_state.register_state, &new_val);
      reg_val =
          VG_(indexXA)(io_vec->initial_state.register_state,
                       VG_(sizeXA)(io_vec->initial_state.register_state) - 1);
    }

    if (!reg_val->is_ptr) {
      SE_(fuzz_region)
      (seed, (Addr)&reg_val->value,
       (Addr)&reg_val->value + sizeof(reg_val->value) - 1);
    }
  }
}

/**
 * @brief Fuzzes values for GPRs and allocated memory
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
  server->using_fuzzed_io_vec = True;
  server->using_existing_io_vec = False;

  /* Fuzz input pointers */
  fuzz_input_pointers(server->current_io_vec, &SE_(seed));
  fuzz_registers(server->current_io_vec, &SE_(seed));

  //  VG_(memcpy)
  //  (&server->current_io_vec->initial_state.register_state.buf[VG_O_FRAME_PTR],
  //   &server->initial_frame_ptr, sizeof(server->initial_frame_ptr));
  //  VG_(memcpy)
  //  (&server->current_io_vec->initial_state.register_state.buf[VG_O_STACK_PTR],
  //   &server->initial_stack_ptr, sizeof(server->initial_stack_ptr));

  return SE_(set_server_state)(server, SERVER_WAITING_TO_EXECUTE);
}

/**
 * @brief Reads in the IOVec from cmd_msg, allocates areas specified, and
 * sets those memory areas according to the seed
 * @param server
 * @param cmd_msg
 * @return
 */
static Bool handle_set_io_vec(SE_(cmd_server) * server,
                              SE_(cmd_msg) * cmd_msg) {
  tl_assert(server);
  tl_assert(cmd_msg);
  tl_assert(cmd_msg->msg_type == SEMSG_SET_CTX);
  tl_assert(cmd_msg->length > 0);
  tl_assert(cmd_msg->data);

  if (!SE_(set_server_state)(server, SERVER_SETTING_CTX)) {
    return False;
  }

  if (server->current_io_vec) {
    SE_(free_io_vec)(server->current_io_vec);
  }
  server->current_io_vec =
      SE_(read_io_vec_from_buf)(cmd_msg->length, (UChar *)cmd_msg->data);

  //  SE_(ppIOVec)(server->current_io_vec);
  UInt seed = server->current_io_vec->random_seed;
  //  VG_(umsg)("Seed = %u\n", seed);

  /* Establish valid memory state */
  UInt size =
      VG_(sizeRangeMap)(server->current_io_vec->initial_state.address_state);
  UWord obj_min_addr = 0, obj_max_addr = 0;
  for (UInt i = 0; i < size; i++) {
    UWord addr_min, addr_max, val;
    VG_(indexRangeMap)
    (&addr_min, &addr_max, &val,
     server->current_io_vec->initial_state.address_state, i);
    if (val & OBJ_START_MAGIC) {
      obj_min_addr = addr_min;
    } else if (val & OBJ_END_MAGIC) {
      obj_max_addr = addr_max;

      SysRes res = VG_(am_mmap_anon_fixed_client)(
          obj_min_addr, obj_max_addr - obj_min_addr,
          VKI_PROT_READ | VKI_PROT_WRITE);
      if (sr_isError(res)) {
        VG_(umsg)
        ("Could not allocate %lu bytes at %p!\n", obj_max_addr - obj_min_addr,
         (void *)obj_min_addr);
        return False;
      }
    }
  }

  /* Set initial memory values based on the random seed provided by the IOVec */
  fuzz_input_pointers(server->current_io_vec, &seed);
  /* No need to fuzz registers, since the ''fuzzed`` registers come in with
   * the initial state */

  //  SE_(ppIOVec)(server->current_io_vec);

  server->using_existing_io_vec = True;
  server->using_fuzzed_io_vec = False;

  return SE_(set_server_state)(server, server->target_func_addr > 0
                                           ? SERVER_WAITING_TO_EXECUTE
                                           : SERVER_WAIT_FOR_CMD);
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
      report_success(server, 0, NULL);
    }
    break;
  case SEMSG_COVERAGE:
    write_coverage_to_commander(server);
    msg_handled = True;
    break;
  case SEMSG_EXECUTE:
    msg_handled = SE_(set_server_state)(server, SERVER_EXECUTING);
    //    if (!msg_handled) {
    //      VG_(umsg)
    //      ("Could not set execution state from %s\n",
    //       SE_(server_state_str)(server->current_state));
    //    } else {
    //      VG_(umsg)
    //      ("Server state set to %s\n",
    //       SE_(server_state_str)(server->current_state));
    //    }
    /* We want to fork a new process to actually execute the target code */
    parent_should_fork = True;
    break;
  case SEMSG_SET_CTX:
    msg_handled = handle_set_io_vec(server, cmd_msg);
    if (msg_handled) {
      report_success(server, 0, NULL);
    }
    break;
  case SEMSG_RESET:
    SE_(reset_server)(server);
    report_success(server, 0, NULL);
    msg_handled = True;
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
 * @param location of object if known
 * @return NULL on error
 */
static Addr allocate_new_object(SE_(cmd_server) * server, SizeT size,
                                Addr location) {
  tl_assert(size > 0);

  Addr new_alloc_loc;

  if (!location) {
    SysRes res =
        VG_(am_mmap_anon_float_client)(size, VKI_PROT_READ | VKI_PROT_WRITE);
    if (sr_isError(res)) {
      return 0;
    }
    VG_(memset)(&new_alloc_loc, 0, sizeof(new_alloc_loc));
    Int addr = sr_Res(res);
    VG_(memcpy)(&new_alloc_loc, &addr, sizeof(addr));
  } else {
    if (!VG_(am_is_valid_for_client_or_free_or_resvn)(
            location, size, VKI_PROT_READ | VKI_PROT_WRITE)) {
      VG_(umsg)("%p cannot ever be a valid client address\n", (void *)location);
      return 0;
    }
    new_alloc_loc = location;
  }

  if (!new_alloc_loc) {
    return 0;
  }

  //  VG_(umsg)("Allocating %lu bytes at %p\n", size, (void *)new_alloc_loc);

  /* Mark the start and end points of the object */
  VG_(bindRangeMap)
  (server->current_io_vec->initial_state.address_state, new_alloc_loc,
   new_alloc_loc, OBJ_START_MAGIC | OBJ_ALLOCATED_MAGIC);
  VG_(bindRangeMap)
  (server->current_io_vec->initial_state.address_state, new_alloc_loc + 1,
   new_alloc_loc + size - 2, OBJ_ALLOCATED_MAGIC);
  VG_(bindRangeMap)
  (server->current_io_vec->initial_state.address_state,
   new_alloc_loc + size - 1, new_alloc_loc + size - 1,
   OBJ_END_MAGIC | OBJ_ALLOCATED_MAGIC);

  return new_alloc_loc;
}

/**
 * @brief Reallocates an object, and puts the new bounds in the pointers
 * @param server
 * @param new_size
 * @param obj_start
 * @param obj_end
 * @param new_start
 * @param new_end
 * @param new_bytes
 * @return
 */
static Bool reallocate_obj(SE_(cmd_server) * server, SizeT new_size,
                           Addr obj_start, Addr obj_end, Addr *new_start,
                           Addr *new_end, PtrdiffT new_bytes) {
  tl_assert(server);
  tl_assert(new_start);
  tl_assert(new_end);
  tl_assert(new_size > 0);
  tl_assert(obj_start < obj_end);

  SizeT current_size = obj_end - obj_start + 1;
  //  VG_(umsg)("current_size = %lu\tnew_size = %lu\n", current_size, new_size);
  if (new_size <= current_size) {
    *new_start = obj_start;
    *new_end = obj_end;
    return True;
  }

  Addr new_addr = allocate_new_object(server, new_size, (Addr)NULL);
  if (!new_addr) {
    return False;
  }

  /* Copy existing mapping to new object */
  UWord min_addr, max_addr, val;
  for (Int i = 0; i < current_size; i++) {
    VG_(lookupRangeMap)
    (&min_addr, &max_addr, &val,
     server->current_io_vec->initial_state.address_state, obj_start + i);

    tl_assert(val & OBJ_ALLOCATED_MAGIC);

    // Ensure that bounds are correctly maintained
    if (val & OBJ_END_MAGIC) {
      val ^= OBJ_END_MAGIC;
    }
    if (val & OBJ_START_MAGIC) {
      val ^= OBJ_START_MAGIC;
    }

    Addr dest = new_addr + i;
    if (new_bytes < 0) {
      dest += -new_bytes;
    }

    /* Copy over any pointers */
    if (val & ALLOCATED_SUBPTR_MAGIC) {
      UWord tmp_min, tmp_max, tmp_val;
      VG_(lookupRangeMap)
      (&tmp_min, &tmp_max, &tmp_val,
       server->current_io_vec->initial_state.pointer_member_locations,
       obj_start + i);
      tl_assert(tmp_val > 0);
      //      VG_(umsg)
      //      ("Copying pointer byte from %p to %p\n", (void *)(obj_start + i),
      //       (void *)(new_addr + i));
      VG_(memcpy)
      ((void *)(new_addr + i), (void *)(obj_start + i), sizeof(Char));
      VG_(bindRangeMap)
      (server->current_io_vec->initial_state.pointer_member_locations,
       obj_start + i, obj_start + i, 0);
      VG_(bindRangeMap)
      (server->current_io_vec->initial_state.pointer_member_locations,
       new_addr + i, new_addr + i, tmp_val);
    }

    VG_(bindRangeMap)
    (server->current_io_vec->initial_state.address_state, dest, dest, val);
  }

  VG_(bindRangeMap)
  (server->current_io_vec->initial_state.address_state, obj_start, obj_end, 0);

  UInt map_size = VG_(sizeRangeMap)(
      server->current_io_vec->initial_state.pointer_member_locations);
  for (UInt i = 0; i < map_size; i++) {
    VG_(indexRangeMap)
    (&min_addr, &max_addr, &val,
     server->current_io_vec->initial_state.pointer_member_locations, i);
    //    if (val > 0) {
    //      VG_(umsg)
    //      ("[ %p -- %p ] = 0x%lx\n", (void *)min_addr, (void *)max_addr, val);
    //    }
    if (val == obj_start) {
      VG_(bindRangeMap)
      (server->current_io_vec->initial_state.pointer_member_locations, min_addr,
       max_addr, new_addr);
    }
  }

  Bool needs_discard;
  SysRes res =
      VG_(am_munmap_client)(&needs_discard, obj_start, obj_end - obj_start);
  if (sr_isError(res)) {
    VG_(umsg)
    ("Failed to unmap [%p -- %p] from client!\n", (void *)obj_start,
     (void *)obj_end);
  }
  *new_start = new_addr;
  *new_end = new_addr + new_size - 1;

  //  VG_(umsg)
  //  ("Reallocated object from [%p - %p] to [%p - %p]\n", (void *)obj_start,
  //   (void *)obj_end, (void *)*new_start, (void *)*new_end);

  return True;
}

/**
 * @brief Writes ptr_val to the offset, and registers the region covered by the
 * pointer as containing a pointer
 * @param server
 * @param obj_start
 * @param obj_end
 * @param submember_offset
 * @param ptr_val
 */
static void set_pointer_submember(SE_(cmd_server) * server, Addr obj_start,
                                  Addr obj_end, SizeT submember_offset,
                                  Addr ptr_val) {
  tl_assert(server);
  tl_assert(obj_start);
  tl_assert(submember_offset >= 0);
  tl_assert(obj_end - obj_start + 1 >= sizeof(Addr));

  //  VG_(umsg)
  //  ("Setting %p + %lu = %p\n", (void *)obj_start, submember_offset,
  //   (void *)ptr_val);
  UWord min_addr, max_addr, val;
  Addr pointer_start = obj_start + submember_offset;
  for (Int i = 0; i < sizeof(Addr); i++) {
    VG_(lookupRangeMap)
    (&min_addr, &max_addr, &val,
     server->current_io_vec->initial_state.address_state, pointer_start + i);

    tl_assert(val & OBJ_ALLOCATED_MAGIC);

    val |= ALLOCATED_SUBPTR_MAGIC;

    //    VG_(umsg)("Registering %p = %lu\n", (void *)(pointer_start + i), val);
    VG_(bindRangeMap)
    (server->current_io_vec->initial_state.address_state, pointer_start + i,
     pointer_start + i, val);
  }
  VG_(bindRangeMap)
  (server->current_io_vec->initial_state.pointer_member_locations,
   (UWord)pointer_start, (UWord)pointer_start + sizeof(Addr) - 1, ptr_val);

  VG_(memcpy)((void *)pointer_start, &ptr_val, sizeof(Addr));
}

/**
 * @brief Looks up if addr is in a previously allocated object
 * @param server
 * @param addr
 * @return True if the addr is in a previously allocated object
 */
static Bool lookup_obj(SE_(cmd_server) * server, Addr addr, Addr *obj_start,
                       Addr *obj_end) {
  tl_assert(server);
  tl_assert(server->current_io_vec);

  //  VG_(umsg)("Trying to find %p\n", (void *)addr);

  UInt size =
      VG_(sizeRangeMap)(server->current_io_vec->initial_state.address_state);

  UWord min_addr, max_addr, val;
  Bool in_obj = False;
  UWord obj_start_addr = 0, obj_end_addr = 0;
  for (Int i = 0; i < size; i++) {
    VG_(indexRangeMap)
    (&min_addr, &max_addr, &val,
     server->current_io_vec->initial_state.address_state, i);

    if (val & OBJ_START_MAGIC) {
      obj_start_addr = min_addr;
      in_obj = True;
    } else if (in_obj && (val & OBJ_END_MAGIC)) {
      obj_end_addr = max_addr;

      if (addr >= obj_start_addr && addr <= obj_end_addr) {
        if (obj_start) {
          *obj_start = obj_start_addr;
        }
        if (obj_end) {
          *obj_end = obj_end_addr;
        }
        return True;
      }

      obj_start_addr = 0;
      obj_end_addr = 0;
      in_obj = False;
    }
  }

  if (obj_start) {
    *obj_start = 0;
  }
  if (obj_end) {
    *obj_end = 0;
  }
  return False;
}

/**
 * @brief Searches the memory area around addr for allocated objects
 * @param server
 * @param addr
 * @return
 */
static Bool object_nearby(SE_(cmd_server) * server, Addr addr,
                          Addr *closest_min, Addr *closest_max) {
  Addr min_addr = VG_PGROUNDDN(addr);
  Addr max_addr = VG_PGROUNDUP(addr);
  Addr curr;

  Addr closest_low_start = 0, closest_low_end = 0;
  Addr closest_high_start = 0, closest_high_end = 0;
  //  VG_(umsg)("Searching for objects near %p\n", (void *)addr);

  for (curr = addr; curr >= min_addr; curr -= sizeof(Int)) {
    if (lookup_obj(server, curr, &closest_low_start, &closest_low_end)) {
      break;
    }
  }

  //  VG_(umsg)
  //  ("closest_low: [ %p -- %p ]\n", (void *)closest_low_start,
  //   (void *)closest_low_end);

  if (curr == addr && closest_low_start > 0) {
    /* We are already in an object */
    if (closest_min) {
      *closest_min = closest_low_start;
    }
    if (closest_max) {
      *closest_max = closest_low_end;
    }
    return True;
  }

  for (curr = addr; curr <= max_addr; curr += sizeof(Int)) {
    if (lookup_obj(server, curr, &closest_high_start, &closest_high_end)) {
      break;
    }
  }

  //  VG_(umsg)
  //  ("closest_high: [ %p -- %p ]\n", (void *)closest_high_start,
  //   (void *)closest_high_end);

  if (closest_low_start == 0 && closest_high_start == 0) {
    /* There are no objects nearby */
    if (closest_min) {
      *closest_min = 0;
    }
    if (closest_max) {
      *closest_max = 0;
    }

    return False;
  }

  SizeT distance_low = addr - closest_low_end;
  /* If no high object is found, then this will be negative,
   * but since SizeT is unsigned, then the resulting number
   * will be a very high positive number */
  SizeT distance_high = closest_high_start - addr;
  if (distance_high > distance_low) {
    if (closest_min) {
      *closest_min = closest_low_start;
    }
    if (closest_max) {
      *closest_max = closest_low_end;
    }
  } else {
    if (closest_min) {
      *closest_min = closest_high_start;
    }
    if (closest_max) {
      *closest_max = closest_high_end;
    }
  }

  return True;
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

  Word count, i;
  Addr obj_loc = 0;
  Word bytes_read = 0;
  Addr obj_start = 0, obj_end = 0;

  SE_(register_value) * reg_val;

  SE_(tainted_loc) invalid_addr;
  SE_(tainted_loc) tainted_loc;
  VG_(memcpy)
  (&invalid_addr, (UChar *)new_alloc_msg->data + bytes_read,
   sizeof(SE_(tainted_loc)));
  bytes_read += sizeof(SE_(tainted_loc));

  VG_(memcpy)(&count, (UChar *)new_alloc_msg->data + bytes_read, sizeof(Word));
  bytes_read += sizeof(Word);
  for (i = 0; i < count; i++) {
    VG_(memcpy)
    (&tainted_loc, (UChar *)new_alloc_msg->data + bytes_read,
     sizeof(tainted_loc));
    bytes_read += sizeof(tainted_loc);

    if (tainted_loc.type == taint_addr || tainted_loc.type == taint_stack) {
      VG_(umsg)
      ("Received tainted %s %p\n",
       tainted_loc.type == taint_stack ? "stack address" : "address",
       (void *)tainted_loc.location.addr);
      AddrInfo a;
      VG_(describe_addr)(VG_(current_DiEpoch)(), tainted_loc.location.addr, &a);
      VG_(pp_addrinfo)(tainted_loc.location.addr, &a);
      VG_(clear_addrinfo)(&a);
    } else if (tainted_loc.type == taint_reg) {
      VG_(umsg)("Received tainted register %d\n", tainted_loc.location.offset);
    } else {
      VG_(umsg)("Received invalid taint\n");
    }

    switch (tainted_loc.type) {
    case taint_reg:
      if (tainted_loc.location.offset == VG_O_STACK_PTR ||
          tainted_loc.location.offset == VG_O_FRAME_PTR ||
          tainted_loc.location.offset == VG_O_INSTR_PTR) {
        VG_(umsg)("Invalid tainted register:\n\t");
        SE_(ppTaintedLocation(&tainted_loc));
        return False;
      }

      reg_val = NULL;
      for (UInt j = 0;
           j <
           VG_(sizeXA)(server->current_io_vec->initial_state.register_state);
           j++) {
        SE_(register_value) *tmp = VG_(indexXA)(
            server->current_io_vec->initial_state.register_state, j);
        if (tmp->guest_state_offset == tainted_loc.location.offset) {
          reg_val = tmp;
          break;
        }
      }
      if (!reg_val) {
        VG_(umsg)
        ("Could not find register %d in IOVec register state\n",
         tainted_loc.location.offset);
        return False;
      }

      if (reg_val->is_ptr) {
        /* This register has been allocated, so extend the existing object */
        if (invalid_addr.type != taint_addr) {
          VG_(umsg)("Invalid tainted address\n");
          return False;
        }

        if (!lookup_obj(server, (Addr)reg_val->value, &obj_start, &obj_end)) {
          VG_(umsg)
          ("Failed to find expected object allocated to register %d\n",
           tainted_loc.location.offset);
          return False;
        }

        /* Allocate larger object and free existing object if needed, and
         * set sub-member as a pointer */
        SizeT ptr_member_offset = invalid_addr.location.addr - obj_start;
        SizeT needed_size = ptr_member_offset + sizeof(Addr);
        if (!reallocate_obj(server, needed_size, obj_start, obj_end, &obj_start,
                            &obj_end, 0)) {
          VG_(umsg)
          ("Could not reallocate object for register %d\n",
           tainted_loc.location.offset);
          return False;
        }

        Addr submember =
            allocate_new_object(server, SE_DEFAULT_ALLOC_SPACE, (Addr)NULL);
        if (!submember) {
          VG_(umsg)("Could not allocate submember object\n");
          return False;
        }

        set_pointer_submember(server, obj_start, obj_end, ptr_member_offset,
                              submember);

        reg_val->value = (RegWord)obj_start;
        break;
      } else {
        /* This register hasn't been allocated before */
        obj_loc =
            allocate_new_object(server, SE_DEFAULT_ALLOC_SPACE, (Addr)NULL);
        if (!obj_loc) {
          VG_(umsg)("Failed to allocate new object\n");
          return False;
        }
        //        VG_(umsg)
        //        ("Setting register %d to %p\n", tainted_loc.location.offset,
        //         (void *)(obj_loc));
        reg_val->is_ptr = True;
        reg_val->value = obj_loc;
      }
      break;
    case taint_stack:
      if (tainted_loc.location.addr < server->min_stack_ptr) {
        /* The stack needs to be expanded */
        if (!VG_(extend_stack)(server->executor_tid,
                               tainted_loc.location.addr)) {
          VG_(umsg)
          ("Failed to extend stack to %p\n", (void *)tainted_loc.location.addr);
          return False;
        }
        /* We just needed to adjust the stack, so this attempt doesn't count */
        server->attempt_count--;
        server->min_stack_ptr = tainted_loc.location.addr;
        break;
      }
      /* TODO: A stack object needs to be resized */
      /* Purposeful fallthrough */
    case taint_addr:
      if (!object_nearby(server, invalid_addr.location.addr, &obj_start,
                         &obj_end)) {
        if (!VG_(am_is_valid_for_client)(tainted_loc.location.addr,
                                         SE_DEFAULT_ALLOC_SPACE,
                                         VKI_PROT_READ | VKI_PROT_WRITE)) {
          SysRes res = VG_(am_mmap_anon_fixed_client)(
              VG_PGROUNDDN(tainted_loc.location.addr), VKI_PAGE_SIZE,
              VKI_PROT_READ | VKI_PROT_WRITE);
          if (sr_isError(res)) {
            VG_(umsg)
            ("Failed to memory map location %p: %lu\n",
             (void *)VG_PGROUNDDN((void *)tainted_loc.location.addr),
             sr_Err(res));
            return False;
          }
        }
        obj_loc = allocate_new_object(server, SE_DEFAULT_ALLOC_SPACE,
                                      tainted_loc.location.addr);
        if (!obj_loc) {
          VG_(umsg)("Failed to allocate object\n");
          return False;
        }
        //        VG_(umsg)
        //        ("Registered %p as an object\n", (void
        //        *)tainted_loc.location.addr);
      } else {
        PtrdiffT offset = invalid_addr.location.addr - obj_start;
        SizeT orig_size = obj_end - obj_start + 1;
        SizeT new_size;
        if (offset > 0 && offset >= orig_size) {
          new_size = invalid_addr.location.addr + sizeof(Addr) - obj_start;
        } else if (offset > 0 && offset <= orig_size) {
          new_size = orig_size;
        } else {
          new_size = obj_end - invalid_addr.location.addr + 1;
        }

        //        VG_(umsg)
        //        ("Existing object found at [ %p -- %p ] at or near %p. "
        //         "Reallocating to hold %lu bytes.\n",
        //         (void *)obj_start, (void *)obj_end, (void
        //         *)invalid_addr.location.addr, new_size);
        Addr new_start, new_end;
        if (!reallocate_obj(server, new_size, obj_start, obj_end, &new_start,
                            &new_end, offset)) {
          VG_(umsg)
          ("Could not reallocate object at %p to accomodate new size of %lu\n",
           (void *)obj_start, new_size);
          return False;
        }

        Addr sub_pointer =
            allocate_new_object(server, SE_DEFAULT_ALLOC_SPACE, (Addr)NULL);
        if (!sub_pointer) {
          VG_(umsg)("Could not allocate new subpointer object!\n");
          return False;
        }
        if (offset < 0) {
          offset = 0;
        }

        set_pointer_submember(server, new_start, new_end, offset, sub_pointer);
        //        VG_(umsg)
        //        ("Subpointer at %p = 0x%0lx\n", (void *)(new_start + offset),
        //         *(Addr *)(new_start + offset));
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

  Bool should_fork = False;

  struct vki_pollfd fds[1];
  fds[0].fd = server->executor_pipe[0];
  fds[0].events = VKI_POLLIN | VKI_POLLHUP | VKI_POLLPRI;
  //  VG_(umsg)
  //  ("Waiting for child process %d for %u ms\n", server->running_pid,
  //   SE_(MaxDuration));
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
      //      VG_(umsg)
      //      ("Got %s message from executor\n",
      //      SE_(msg_type_str)(cmd_msg->msg_type));
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
        } else if (cmd_msg->data == NULL) {
          report_error(server, NULL);
          goto cleanup;
        }

        VexGuestArchState guest_state;
        VG_(memcpy)
        (&guest_state, cmd_msg->data, cmd_msg->length);
        SE_(free_msg)(cmd_msg);
        VG_(memcpy)
        (&server->initial_stack_ptr, ((UChar *)&guest_state + VG_O_STACK_PTR),
         sizeof(server->initial_stack_ptr));
        server->initial_frame_ptr = server->initial_stack_ptr;
        server->min_stack_ptr = server->initial_stack_ptr;
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
  //  wait_result = VG_(waitpid)(server->running_pid, &status, VKI_WNOHANG);
  //  VG_(umsg)("Wait result = %d\tstatus = %d\n", wait_result, status);
  //  if (wait_result < 0 || (!WIFEXITED(status) && !WIFSIGNALED(status))) {
  VG_(kill)(server->running_pid, VKI_SIGKILL);
  //  }

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

    if (VG_(pipe)(server->executor_pipe) < 0) {
      report_error(server, "Pipe failed");
      goto exit;
    }

    VG_(umsg)
    ("Server forking %u with status %s\n", server->attempt_count,
     SE_(server_state_str)(server->current_state));

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

    //    VG_(umsg)
    //    ("Current server status: %s\n",
    //     SE_(server_state_str)(server->current_state));
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
      } /*else {
        VG_(umsg)
        ("Server NOT forking with status %s\n",
         SE_(server_state_str)(server->current_state));
      }*/
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
  server->min_stack_ptr = -1;

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