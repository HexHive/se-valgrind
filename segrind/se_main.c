/*--------------------------------------------------------------------*/
/*--- SEgrind: The Software Ethology Tool.               se_main.c ---*/
/*--------------------------------------------------------------------*/

/*

   Copyright (C) 2020 Derrick McKee
      derrick@geth.systems

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.

   The GNU General Public License is contained in the file COPYING.
*/

#include "se.h"
#include "se_command_server.h"
#include "se_defs.h"
#include "se_io_vec.h"
#include "se_taint.h"
#include <libvex_ir.h>

#include "libvex.h"
#include "libvex_ir.h"
#include "pub_tool_basics.h"
#include "pub_tool_guest.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_oset.h"
#include "pub_tool_rangemap.h"
#include "pub_tool_signals.h"
#include "pub_tool_stacktrace.h"
#include "pub_tool_xarray.h"

#include "../coregrind/pub_core_scheduler.h"

/**
 * @brief Is the guest executing code?
 */
static Bool client_running = False;
/**
 * @brief Has the reference to main been replaced with the target function?
 */
static Bool main_replaced = False;
/**
 * @brief Has the target function been called?
 */
static Bool target_called = False;
/**
 * @brief The executor thread
 */
static ThreadId target_id = VG_INVALID_THREADID;
/**
 * @brief The server that receives commands from outside, and forks to execute
 * the target function
 */
static SE_(cmd_server) * SE_(command_server) = NULL;
/**
 * @brief The set of unique system calls executed by the target function
 */
static OSet *syscalls = NULL;
/**
 * @brief Per-instruction program states saved for taint analysis
 */
static XArray *program_states = NULL;
/**
 * @brief The range of addresses an IRSB covers
 */
static RangeMap *irsb_ranges = NULL;
/**
 * @brief The name of the target function
 */
static HChar *target_name = NULL;

/**
 * @brief Used for recursive calls
 */
static Int recursive_target_call_count = 0;

static void SE_(report_failure_to_commander)(void);
static void fix_address_space(void);

/**
 * @brief Writes SEMSG_OK msg with io_vec to the commander process
 * @param io_vec
 * @param free_io_vec - True if the IOVec should be freed
 * @return the number of bytes written to the server
 */
static SizeT SE_(write_io_vec_to_cmd_server)(SE_(io_vec) * io_vec,
                                             Bool free_io_vec) {
  tl_assert(SE_(command_server));
  tl_assert(io_vec);

  SizeT bytes_written = SE_(write_io_vec_to_fd)(
      SE_(command_server)->executor_pipe[1], SEMSG_OK, io_vec);

  if (free_io_vec) {
    SE_(free_io_vec)(io_vec);
  }
  return bytes_written;
}

static SizeT SE_(write_coverage_to_cmd_server)(void) {
  tl_assert(SE_(command_server));
  tl_assert(program_states);

  OSet *uniq_insts =
      VG_(OSetWord_Create)(VG_(malloc), SE_TOOL_ALLOC_STR, VG_(free));
  for (Word i = 0; i < VG_(sizeXA)(program_states); i++) {
    VexGuestArchState *tmp =
        (VexGuestArchState *)VG_(indexXA)(program_states, i);
    if (!VG_(OSetWord_Contains)(uniq_insts, tmp->VG_INSTR_PTR)) {
      VG_(OSetWord_Insert)(uniq_insts, tmp->VG_INSTR_PTR);
    }
  }

  SE_(cmd_msg) msg;
  msg.msg_type = SEMSG_COVERAGE;
  msg.length = SE_(Memoize_OSetWord)(uniq_insts, (UChar **)&msg.data);

  SizeT bytes_written =
      SE_(write_msg_to_fd)(SE_(command_server)->executor_pipe[1], &msg, False);

  VG_(free)(msg.data);
  VG_(OSetWord_Destroy)(uniq_insts);
  return bytes_written;
}

/**
 * @brief Records the executed system calls to SE_(current_io_vec),
 * captures the current program state in the expected_state member, then
 * writes the IOVec to the commander process
 */
static void SE_(send_fuzzed_io_vec)(void) {
  UWord syscall_num;
  while (VG_(OSetWord_Next)(syscalls, &syscall_num)) {
    VG_(OSetWord_Insert)
    (SE_(command_server)->current_io_vec->system_calls, syscall_num);
  }
  VG_(get_shadow_regs_area)
  (target_id,
   (UChar *)&SE_(command_server)->current_io_vec->expected_state.register_state,
   0, 0,
   sizeof(SE_(command_server)->current_io_vec->expected_state.register_state));

  tl_assert(SE_(write_io_vec_to_cmd_server)(SE_(command_server)->current_io_vec,
                                            True) > 0);
}

/**
 * Peforms any necessary freeing of allocated objects, sets state variables,
 * releases any held locks, then calls VG_(exit)(0)
 */
static void SE_(cleanup_and_exit)(void) {
  VG_(umsg)("Cleaning up before exiting\n");
  client_running = False;
  main_replaced = False;
  target_id = VG_INVALID_THREADID;

  if (program_states) {
    VG_(deleteXA)(program_states);
    program_states = NULL;
  }
  if (syscalls) {
    VG_(OSetWord_Destroy)(syscalls);
    syscalls = NULL;
  }
  if (target_name) {
    VG_(free)(target_name);
    target_name = NULL;
  }
  if (irsb_ranges) {
    VG_(deleteRangeMap)(irsb_ranges);
    irsb_ranges = NULL;
  }

  if (SE_(cmd_in) > 0) {
    VG_(close)(SE_(cmd_in));
    SE_(cmd_in) = -1;
  }

  if (SE_(cmd_out) > 0) {
    VG_(close)(SE_(cmd_out));
    SE_(cmd_out) = -1;
  }

  if (SE_(log) > 0) {
    VG_(close)(SE_(log));
    SE_(log) = -1;
  }

  if (SE_(command_server)) {
    SE_(free_server)(SE_(command_server));
    SE_(command_server) = NULL;
  }

  VG_(release_BigLock_LL)(NULL);
  VG_(exit)(0);
}

static void SE_(post_clo_init)(void) {
  SE_(command_server) = SE_(make_server)(SE_(cmd_in), SE_(cmd_out));
  VG_(umsg)("Command Server created!\n");
}

/**
 * @brief Returns the first instruction address of the IRSB
 * @param irsb
 * @return
 */
static Addr get_IRSB_start(IRSB *irsb) {
  tl_assert(irsb);
  for (Int i = 0; i < irsb->stmts_used; i++) {
    IRStmt *stmt = irsb->stmts[i];
    if (stmt->tag == Ist_IMark) {
      return stmt->Ist.IMark.addr;
    }
  }
  tl_assert(0);
}

/**
 * @brief Performs taint analysis of executed instructions to find source of
 * segfault. Backwards taint propagation policy:
 * |=====================================================|
 * | Instruction | t tainted? | u Tainted | Taint Policy |
 * |-----------------------------------------------------|
 * |   t = u     |      Y     |     N     |  T(u); R(t)  |
 * |=====================================================|
 */
static void fix_address_space() {
  tl_assert(VG_(sizeXA)(program_states) > 0);

  VexGuestArchState *last_state =
      VG_(indexXA)(program_states, VG_(sizeXA)(program_states) - 1);
  Addr faulting_addr = last_state->VG_INSTR_PTR;

  VG_(umsg)
  ("last_state->STACK_PTR = %p (0x%lx)\n", (void *)last_state->VG_STACK_PTR,
   *(RegWord *)last_state->VG_STACK_PTR);

  VexGuestArchState *current_state;
  VexArch guest_arch;
  VexArchInfo guest_arch_info;
  VexAbiInfo abi_info;
  Word idx;
  UWord irsb_start = 0, irsb_end, val;
  IRSB *irsb = NULL;

  SE_(init_taint_analysis)(program_states);

  VG_(machine_get_VexArchInfo)(&guest_arch, &guest_arch_info);
  LibVEX_default_VexAbiInfo(&abi_info);

  /* Try to get around asserts */
  // FIXME: Is this value ok for other architectures?
  abi_info.guest_stack_redzone_size = 128;

  Bool found_faulting_addr = False;
  Bool in_first_block = True;

  Word stmt_idx = VG_(sizeXA)(program_states);
  for (idx = VG_(sizeXA)(program_states) - 1; idx >= 0; idx--) {
    current_state = VG_(indexXA)(program_states, idx);
    Addr inst_addr = current_state->VG_INSTR_PTR;

    SE_(clear_temps)();

    /* Find the basic block range we are currently in */
    VG_(lookupRangeMap)
    (&irsb_start, &irsb_end, &val, irsb_ranges, (UWord)inst_addr);
    if (!val) {
      const HChar *func_name;
      VG_(get_fnname)
      (VG_(current_DiEpoch)(), SE_(command_server)->target_func_addr,
       &func_name);
      VG_(umsg)
      ("Could not find IRSB bounds at 0x%lx (%s)!\n", inst_addr, func_name);
      SE_(report_failure_to_commander)();
    }
    //    VG_(umsg)
    //    ("Found IRSB range [0x%lx - 0x%lx] for instruction 0x%lx\n",
    //    irsb_start,
    //     irsb_end, inst_addr);

    if (!irsb || irsb_start != get_IRSB_start(irsb)) {
      //      VG_(umsg)
      //      ("Creating new IRSB for range [0x%lx - 0x%lx]\n", irsb_start,
      //      irsb_end);
      vexSetAllocModeTEMP_and_clear();
      Long offset = 0;
      irsb = emptyIRSB();

      /* Find the instructions that are part of the basic block */
      Word bbIdx;
      for (bbIdx = idx - 1; bbIdx >= 0; bbIdx--) {
        VexGuestArchState *tmpState = VG_(indexXA)(program_states, bbIdx);
        if (!(tmpState->VG_INSTR_PTR >= irsb_start &&
              tmpState->VG_INSTR_PTR <= irsb_end)) {
          break;
        }
      }

      /* Recreate executed block */
      for (Word tmpIdx = bbIdx + 1; tmpIdx <= idx; tmpIdx++) {
        VexGuestArchState *tmpState = VG_(indexXA)(program_states, tmpIdx);
        //        VG_(umsg)
        //        ("Translating Instruction %ld (max %ld) (%p)\n", tmpIdx, idx,
        //         (void *)tmpState->VG_INSTR_PTR);
        offset = (tmpState->VG_INSTR_PTR - irsb_start);
        SE_DISASM_TO_IR(irsb, (const UChar *)irsb_start, offset,
                        tmpState->VG_INSTR_PTR, guest_arch, &guest_arch_info,
                        &abi_info, guest_arch_info.endness, False);
        /* Purposefully add IMark stmt after other instructions since we will
         * be going through the instructions backwards */
        addStmtToIRSB(irsb, IRStmt_IMark(tmpState->VG_INSTR_PTR, 1, 0));
      }

      Word orig_stmt_idx = stmt_idx;
      for (Int i = irsb->stmts_used - 1; i >= 0; i--) {
        IRStmt *stmt = irsb->stmts[i];
        ppIRStmt(stmt);
        VG_(printf)("\n");
        Bool taint_found = SE_(taint_found)();
        switch (stmt->tag) {
        case Ist_IMark:
          stmt_idx--;
          VG_(printf)
          ("\tStack ptr = %p (0x%lx)\n",
           (void *)((VexGuestArchState *)VG_(indexXA)(program_states, stmt_idx))
               ->VG_STACK_PTR,
           *(RegWord *)((VexGuestArchState *)VG_(indexXA)(program_states,
                                                          stmt_idx))
                ->VG_STACK_PTR);
          VG_(printf)
          ("\tFrame ptr = %p (0x%lx)\n",
           (void *)((VexGuestArchState *)VG_(indexXA)(program_states, stmt_idx))
               ->VG_FRAME_PTR,
           ((VexGuestArchState *)VG_(indexXA)(program_states, stmt_idx))
                       ->VG_FRAME_PTR == 0
               ? 0xdeadbeef
               : *(RegWord *)((VexGuestArchState *)VG_(indexXA)(program_states,
                                                                stmt_idx))
                      ->VG_FRAME_PTR);
          if (!found_faulting_addr && stmt->Ist.IMark.addr == faulting_addr) {
            VG_(printf)("\tFound faulting address %p\n", (void *)faulting_addr);

            found_faulting_addr = True;
          }
          continue;
        case Ist_Store:
          if (found_faulting_addr) {
            if (!taint_found) {
              SE_(taint_IRExpr)(stmt->Ist.Store.addr, i);
            } else {
              IRExpr *data = stmt->Ist.Store.data;
              IRExpr *addr = stmt->Ist.Store.addr;
              if (SE_(is_IRExpr_tainted)(addr, stmt_idx) &&
                  !SE_(is_IRExpr_tainted)(data, stmt_idx)) {
                SE_(remove_IRExpr_taint)(addr, stmt_idx);
                SE_(taint_IRExpr)(data, stmt_idx);
              }
            }
          }
          continue;
        case Ist_Put:
          if (stmt->Ist.Put.offset == VG_O_INSTR_PTR) {
            continue;
          }

          if (found_faulting_addr) {
            IRExpr *data = stmt->Ist.Put.data;
            if (!taint_found) {
              SE_(taint_IRExpr)(data, stmt_idx);
            } else if (SE_(guest_reg_tainted)(stmt->Ist.Put.offset) &&
                       !SE_(is_IRExpr_tainted)(data, stmt_idx)) {
              SE_(remove_tainted_reg)(stmt->Ist.Put.offset);
              SE_(taint_IRExpr)(data, stmt_idx);
            }
          }
          continue;
        case Ist_WrTmp:
          if (found_faulting_addr) {
            IRExpr *data = stmt->Ist.WrTmp.data;
            if (SE_(temp_tainted)(stmt->Ist.WrTmp.tmp) &&
                !SE_(is_IRExpr_tainted)(data, stmt_idx)) {
              SE_(remove_tainted_temp)(stmt->Ist.WrTmp.tmp);
              SE_(taint_IRExpr)(data, stmt_idx);
              if (SE_(get_IRExpr)(data)->tag == Iex_Get) {
                IRExpr *g = SE_(get_IRExpr)(data);
                VG_(printf)
                ("\t%d = 0x%lx\n", g->Iex.Get.offset,
                 *(RegWord *)((UChar *)VG_(indexXA)(program_states, stmt_idx) +
                              g->Iex.Get.offset));
              }
            } else if (!SE_(temp_tainted)(stmt->Ist.WrTmp.tmp) &&
                       SE_(is_IRExpr_tainted)(data, stmt_idx)) {
              /* A temporary has been assigned a tainted value, so
               * start looking for its use in the IRSB */
              SE_(remove_IRExpr_taint)(data, stmt_idx);
              SE_(taint_temp)(stmt->Ist.WrTmp.tmp);
              //              VG_(printf)("\tRestarting analysis\n");
              stmt_idx = orig_stmt_idx;
              i = irsb->stmts_used;
              found_faulting_addr = !in_first_block;
            }
          }
          continue;
        default:
          continue;
        }
      }

      idx = bbIdx;
      in_first_block = False;
      stmt_idx = idx;
    }
  }

  OSet *tainted_locations = SE_(get_tainted_locations)();
  Word num_areas = VG_(OSetGen_Size)(tainted_locations);
  tl_assert(num_areas > 0);

  UChar *buf =
      VG_(malloc)(SE_TOOL_ALLOC_STR,
                  sizeof(num_areas) + num_areas * sizeof(SE_(tainted_loc)));
  VG_(memcpy)(buf, &num_areas, sizeof(num_areas));
  Word offset = sizeof(num_areas);
  SE_(tainted_loc) * loc;
  while ((loc = VG_(OSetGen_Next)(tainted_locations))) {
    VG_(memcpy)(buf + offset, loc, sizeof(*loc));
    offset += sizeof(*loc);
  }

  SE_(cmd_msg) *msg = SE_(create_cmd_msg)(
      SEMSG_NEW_ALLOC, sizeof(num_areas) + num_areas * sizeof(SE_(tainted_loc)),
      buf);

  SE_(write_msg_to_fd)(SE_(command_server)->executor_pipe[1], msg, True);

  SE_(end_taint_analysis)();
}

/**
 * @brief Recovers pointer input structures in case of a segfault
 * @param sigNo
 * @param addr
 */
static void SE_(signal_handler)(Int sigNo, Addr addr) {
  if (client_running && target_called) {
    if (sigNo == VKI_SIGSEGV && SE_(command_server)->using_fuzzed_io_vec) {
      fix_address_space();
    } else {
      SE_(report_failure_to_commander)();
    }
    SE_(cleanup_and_exit)();
  }
}

/**
 * @brief Starts the command server, which only returns on exit, but executor
 * processes continue to the end
 * @param tid
 * @param child
 */
static void SE_(thread_creation)(ThreadId tid, ThreadId child) {
  if (!client_running) {
    target_id = child;
    VG_(umsg)("Starting Command Server\n");
    SE_(start_server)(SE_(command_server), child);

    if (SE_(command_server)->current_state != SERVER_EXECUTING &&
        SE_(command_server)->current_state != SERVER_GETTING_INIT_STATE) {
      VG_(exit)(0);
    }

    /* Child executors arrive here */
    VG_(clo_vex_control).iropt_register_updates_default =
        VexRegUpdAllregsAtEachInsn;
    if (syscalls) {
      VG_(OSetWord_Destroy)(syscalls);
    }
    if (program_states) {
      VG_(deleteXA)(program_states);
    }
    if (target_name) {
      VG_(free)(target_name);
    }
    if (irsb_ranges) {
      VG_(deleteRangeMap)(irsb_ranges);
    }

    syscalls = VG_(OSetWord_Create)(VG_(malloc), SE_TOOL_ALLOC_STR, VG_(free));
    program_states = VG_(newXA)(VG_(malloc), SE_TOOL_ALLOC_STR, VG_(free),
                                sizeof(VexGuestArchState));
    irsb_ranges =
        VG_(newRangeMap)(VG_(malloc), SE_TOOL_ALLOC_STR, VG_(free), 0);

    VG_(set_fault_catcher)(SE_(signal_handler));
    VG_(set_call_fault_catcher_in_generated)(True);

    const HChar *fnname;
    VG_(get_fnname)
    (VG_(current_DiEpoch)(), SE_(command_server)->target_func_addr, &fnname);
    target_name = VG_(strdup)(SE_TOOL_ALLOC_STR, fnname);
    tl_assert(VG_(strlen)(target_name) > 0);
    VG_(umsg)("Executing %s\n", target_name);
  }
}

/**
 * @brief Sends SEMSG_OK msg to commander process. Includes full fuzzed IOVec if
 * the command server is using a fuzzed input program state
 */
static void SE_(maybe_report_success_to_commader)(void) {
  tl_assert(client_running);
  tl_assert(main_replaced);

  if (--recursive_target_call_count > 0) {
    return;
  }

  if (SE_(command_server)->using_fuzzed_io_vec &&
      SE_(command_server)->current_state != SERVER_GETTING_INIT_STATE) {
    SE_(send_fuzzed_io_vec)();
  }

  if (SE_(command_server)->needs_coverage &&
      SE_(command_server)->current_state != SERVER_GETTING_INIT_STATE) {
    SE_(write_coverage_to_cmd_server)();
  }

  SE_(cleanup_and_exit)();
}

/**
 * @brief Writes SEMSG_FAIL to commander process
 */
static void SE_(report_failure_to_commander)(void) {
  tl_assert(client_running);

  SE_(write_msg_to_fd)
  (SE_(command_server)->executor_pipe[1],
   SE_(create_cmd_msg)(SEMSG_FAIL, 0, NULL), True);

  SE_(cleanup_and_exit)();
}

static void SE_(thread_exit)(ThreadId tid) {}

/**
 * @brief Sets the input state for the target function upon entry.
 */
static void jump_to_target_function(void) {
  tl_assert(client_running);
  tl_assert(main_replaced);

  if (target_called) {
    recursive_target_call_count++;
    return;
  }

  if (SE_(command_server)->current_state == SERVER_GETTING_INIT_STATE) {
    VexGuestArchState current_state;
    VG_(get_shadow_regs_area)
    (target_id, (UChar *)&current_state, 0, 0, sizeof(current_state));

    VG_(umsg)
    ("Reporting initial state. SP = %p\n", (void *)current_state.VG_STACK_PTR);
    SE_(cmd_msg) *cmd_msg =
        SE_(create_cmd_msg)(SEMSG_OK, sizeof(current_state), &current_state);
    SE_(write_msg_to_fd)(SE_(command_server)->executor_pipe[1], cmd_msg, True);
    SE_(cleanup_and_exit)();
  }

  //  VG_(umsg)
  //  ("SP = %p (0x%lx)\tFP = %p (0x%lx)\n",
  //   (void *)SE_(command_server)
  //       ->current_io_vec->initial_state.register_state.VG_STACK_PTR,
  //   *(RegWord *)(SE_(command_server)
  //                    ->current_io_vec->initial_state.register_state
  //                    .VG_STACK_PTR),
  //   (void *)SE_(command_server)
  //       ->current_io_vec->initial_state.register_state.VG_FRAME_PTR,
  //   *(RegWord *)(SE_(command_server)
  //                    ->current_io_vec->initial_state.register_state
  //                    .VG_FRAME_PTR));
  VG_(umsg)
  ("SP = %p (0x%lx)\tFP = %p (0x%lx)\n", (void *)VG_(get_SP)(target_id),
   VG_(get_SP)(target_id) == 0 ? 0xdeadbeef
                               : *(RegWord *)VG_(get_SP)(target_id),
   (void *)VG_(get_FP)(target_id),
   VG_(get_FP)(target_id) == 0 ? 0xdeadbeef
                               : *(RegWord *)VG_(get_FP)(target_id));

  VG_(umsg)
  ("Setting program state. SP = %p\n",
   (void *)SE_(command_server)
       ->current_io_vec->initial_state.register_state.VG_STACK_PTR);
  VG_(set_shadow_regs_area)
  (target_id, 0, 0,
   sizeof(SE_(command_server)->current_io_vec->initial_state.register_state),
   (UChar *)&SE_(command_server)->current_io_vec->initial_state.register_state);
  target_called = True;

#if defined(VGA_amd64)
  VG_(umsg)
  ("About to execute 0x%lx with RDI = 0x%llx\n", VG_(get_IP)(target_id),
   SE_(command_server)->current_io_vec->initial_state.register_state.guest_RDI);
#endif
}

/**
 * @brief Sets client_running boolean and checks that main has been replaced
 * before it is called.
 * @param tid
 * @param blocks_dispatched
 */
static void SE_(start_client_code)(ThreadId tid, ULong blocks_dispatched) {
  if (!client_running && tid == target_id) {
    client_running = True;
  }

  if (!main_replaced &&
      VG_(get_IP)(target_id) == SE_(command_server)->main_addr) {
    SE_(report_failure_to_commander)();
  }
}

/**
 * @brief Records the current guest state if the client is running, main is
 * replaced, and the target has been called.
 */
static void record_current_state(void) {
  if (client_running && main_replaced && target_called) {
    //    VG_(umsg)("Recording state for 0x%lx\n", VG_(get_IP)(target_id));
    VexGuestArchState current_state;
    VG_(get_shadow_regs_area)
    (target_id, (UChar *)&current_state, 0, 0, sizeof(current_state));
    VG_(addToXA)(program_states, &current_state);
  }
}

/**
 * @brief Returns True if there is 0 or 1 IMark IRStmts between [idx, max)
 * @param idx
 * @param max
 * @param stmts
 * @return
 */
static Bool is_last_IMark(Int idx, Int max, IRStmt **stmts) {
  tl_assert(stmts);

  Int imark_count = 0;
  for (Int i = idx; i < max; i++) {
    IRStmt *stmt = stmts[i];
    if (stmt->tag == Ist_IMark) {
      if (++imark_count > 1) {
        return False;
      }
    }
  }

  return True;
}

/**
 * @brief Adds calls to record_current_state, and report_success to the input
 * IRSB.
 * @param bb
 * @return Instrumented IRSB
 */
static IRSB *SE_(instrument_target)(IRSB *bb) {
  tl_assert(client_running);
  tl_assert(main_replaced);

  IRSB *bbOut;
  Int i;
  IRDirty *di;
  UWord minAddress = 0;
  UWord maxAddress = 0;

  bbOut = deepCopyIRSBExceptStmts(bb);

  const HChar *fnname;
  VG_(get_fnname)(VG_(current_DiEpoch)(), VG_(get_IP)(target_id), &fnname);

  i = 0;
  while (i < bb->stmts_used && bb->stmts[i]->tag != Ist_IMark) {
    addStmtToIRSB(bbOut, bb->stmts[i]);
  }

  /* When we are getting a valid starting program state, we want to
   * get the state after the function preamble has executed. So add
   * the call to jump_to_target_function at the second instruction, not
   * the first.
   */
  for (/* use current i */; i < bb->stmts_used; i++) {
    IRStmt *stmt = bb->stmts[i];

    switch (stmt->tag) {
    case Ist_IMark:
      addStmtToIRSB(bbOut, stmt);
      if (minAddress == 0 || minAddress > (UWord)stmt->Ist.IMark.addr) {
        minAddress = (UWord)stmt->Ist.IMark.addr;
      }
      if (stmt->Ist.IMark.addr > maxAddress) {
        maxAddress = (UWord)stmt->Ist.IMark.addr;
      }
      if (stmt->Ist.IMark.addr == SE_(command_server)->target_func_addr) {
        di = unsafeIRDirty_0_N(0, "jump_to_target_function",
                               VG_(fnptr_to_fnentry)(&jump_to_target_function),
                               mkIRExprVec_0());
        addStmtToIRSB(bbOut, IRStmt_Dirty(di));
      } else if (VG_(strcmp)(fnname, target_name) == 0 &&
                 is_last_IMark(i, bb->stmts_used, bb->stmts) &&
                 bb->jumpkind == Ijk_Ret) {
        di = unsafeIRDirty_0_N(
            0, "maybe_report_success_to_commader",
            VG_(fnptr_to_fnentry)(&SE_(maybe_report_success_to_commader)),
            mkIRExprVec_0());
        addStmtToIRSB(bbOut, IRStmt_Dirty(di));
      }

      di = unsafeIRDirty_0_N(0, "record_current_state",
                             VG_(fnptr_to_fnentry)(&record_current_state),
                             mkIRExprVec_0());
      addStmtToIRSB(bbOut, IRStmt_Dirty(di));
      break;
    case Ist_Exit:
      if (VG_(strcmp)(fnname, target_name) == 0 && bb->jumpkind != Ijk_Boring) {
        di = unsafeIRDirty_0_N(
            0, "maybe_report_success_to_commader",
            VG_(fnptr_to_fnentry)(&SE_(maybe_report_success_to_commader)),
            mkIRExprVec_0());
        addStmtToIRSB(bbOut, IRStmt_Dirty(di));
      } else {
        addStmtToIRSB(bbOut, stmt);
      }
      break;
    default:
      addStmtToIRSB(bbOut, stmt);
      break;
    }
  }

  //  UWord keyMin, keyMax, val;
  //  VG_(lookupRangeMap)(&keyMin, &keyMax, &val, irsb_ranges, minAddress);
  //  if (val == 0) {
  //    VG_(umsg)
  //    ("Creating irsb range [%p - %p]\n", (void *)minAddress, (void
  //    *)maxAddress);
  VG_(bindRangeMap)(irsb_ranges, minAddress, maxAddress, minAddress);
  //  }

  if (VG_(strcmp)(fnname, target_name) == 0) {
    ppIRSB(bbOut);
  }
  return bbOut;
}

/**
 * @brief The address of main is expected to be a constant, so search for
 * a IRConst containing the address of main.  This currently assumes that
 * the address is used in a PUT IRStmt, which may not be valid for all
 * architectures.
 * @param bb
 * @return a copy of bb with an IRConst containing the address of main replaced
 * with the target function address if the main address is found.
 */
static IRSB *SE_(replace_main_reference)(IRSB *bb) {
  tl_assert(client_running);
  tl_assert(!main_replaced);
  tl_assert(!target_called);

  IRSB *bbOut;
  Int i;
  IRExpr *expr;

  bbOut = deepCopyIRSBExceptStmts(bb);

  for (i = 0; i < bb->stmts_used; i++) {
    IRStmt *stmt = bb->stmts[i];
    switch (stmt->tag) {
    case Ist_Put:
      expr = stmt->Ist.Put.data;
      if (expr->tag == Iex_Const) {
        IRConst *irConst = expr->Iex.Const.con;
        if (irConst->tag == Ico_U64 &&
            irConst->Ico.U64 == SE_(command_server)->main_addr) {
          irConst = IRConst_U64((ULong)SE_(command_server)->target_func_addr);
          expr = IRExpr_Const(irConst);
          addStmtToIRSB(bbOut, IRStmt_Put(stmt->Ist.Put.offset, expr));
          main_replaced = True;
        } else if (irConst->tag == Ico_U32 &&
                   irConst->Ico.U32 == SE_(command_server)->main_addr) {
          irConst = IRConst_U32((UInt)SE_(command_server)->target_func_addr);
          expr = IRExpr_Const(irConst);
          addStmtToIRSB(bbOut, IRStmt_Put(stmt->Ist.Put.offset, expr));
          main_replaced = True;
        } else {
          addStmtToIRSB(bbOut, stmt);
        }
      } else {
        addStmtToIRSB(bbOut, stmt);
      }
      break;
    default:
      addStmtToIRSB(bbOut, stmt);
      break;
    }
  }

  return bbOut;
}

static IRSB *SE_(instrument)(VgCallbackClosure *closure, IRSB *bb,
                             const VexGuestLayout *layout,
                             const VexGuestExtents *vge,
                             const VexArchInfo *archinfo_host, IRType gWordTy,
                             IRType hWordTy) {
  IRSB *bbOut = bb;

  if (client_running && main_replaced) {
    bbOut = SE_(instrument_target)(bb);
  } else if (client_running && !main_replaced && !target_called) {
    bbOut = SE_(replace_main_reference)(bb);
  }

  return bbOut;
}

static void SE_(pre_syscall)(ThreadId tid, UInt syscallno, UWord *args,
                             UInt nArgs) {
  if (tid == target_id && client_running && target_called &&
      !VG_(OSetWord_Contains)(syscalls, (UWord)syscallno)) {
    VG_(OSetWord_Insert)(syscalls, (UWord)syscallno);
  }
}

static void SE_(post_syscall)(ThreadId tid, UInt syscallno, UWord *args,
                              UInt nArgs, SysRes res) {}

static void SE_(fini)(Int exitcode) {
  VG_(umsg)("fini called with %d\n", exitcode);
  SE_(cleanup_and_exit)();
}

static void SE_(pre_clo_init)(void) {
  VG_(details_name)("Software Ethology");
  VG_(details_version)(NULL);
  VG_(details_description)("The binary analysis tool");
  VG_(details_copyright_author)
  ("Copyright (C) 2020, and GNU GPL'd, by Derrick McKee.");
  VG_(details_bug_reports_to)("derrick@geth.systems");

  VG_(details_avg_translation_sizeB)(275);

  VG_(basic_tool_funcs)(SE_(post_clo_init), SE_(instrument), SE_(fini));

  VG_(needs_command_line_options)
  (SE_(process_cmd_line_option), SE_(print_usage), SE_(print_debug_usage));

  VG_(track_start_client_code)(SE_(start_client_code));
  VG_(track_pre_thread_ll_create)(SE_(thread_creation));
  VG_(track_pre_thread_ll_exit)(SE_(thread_exit));

  VG_(needs_syscall_wrapper)(SE_(pre_syscall), SE_(post_syscall));

  SE_(seed) = (VG_(getpid)() << 9) ^ VG_(getppid)();

  SE_(set_clo_defaults)();
}

VG_DETERMINE_INTERFACE_VERSION(SE_(pre_clo_init))

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
