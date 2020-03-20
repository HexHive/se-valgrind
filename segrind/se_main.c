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
#include <libvex_ir.h>

#include "libvex.h"
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

static void SE_(report_failure_to_commander)(void);

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

/**
 * @brief Records the executed system calls to SE_(current_io_vec),
 * captures the current program state in the expected_state member, then
 * writes the IOVec to the commander process
 */
static void SE_(send_fuzzed_io_vec)(void) {
  UWord syscall_num;
  while (VG_(OSetWord_Next)(syscalls, &syscall_num)) {
    VG_(OSetWord_Insert)(SE_(current_io_vec)->system_calls, syscall_num);
  }
  VG_(get_shadow_regs_area)
  (target_id, (UChar *)&SE_(current_io_vec)->expected_state, 0, 0,
   sizeof(SE_(current_io_vec)->expected_state));

#if defined(VGA_amd64)
  VG_(umsg)
  ("%s returned 0x%llx\n", target_name,
   SE_(current_io_vec)->expected_state.guest_RAX);
#endif

  tl_assert(SE_(write_io_vec_to_cmd_server)(SE_(current_io_vec), True) > 0);
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
  tl_assert(SE_(command_server));
}

/**
 * @brief Performs taint analysis of executed instructions to find source of
 * segfault. Backwards taint propagation policy:
 * |=====================================================|
 * | Instruction | t tainted? | u Tainted | Taint Policy |
 * |-----------------------------------------------------|
 * |   t = u     |      Y     |     N     |  T(u); R(t)  |
 * |=====================================================|
 * @param faulting_addr
 */
static void fix_address_space(Addr faulting_addr) {
  tl_assert(VG_(sizeXA)(program_states) > 0);

  VexGuestArchState *current_state;
  VexArch guest_arch;
  VexArchInfo guest_arch_info;
  VexAbiInfo abi_info;
  Word idx;
  DisResult res;

  VG_(machine_get_VexArchInfo)(&guest_arch, &guest_arch_info);
  LibVEX_default_VexAbiInfo(&abi_info);

  /* Try to get around asserts */
  abi_info.guest_stack_redzone_size = 128;

  for (idx = VG_(sizeXA)(program_states) - 1; idx >= 0; idx--) {
    vexSetAllocModeTEMP_and_clear();
    IRSB *irsb = emptyIRSB();
    current_state = VG_(indexXA)(program_states, idx);
    Addr inst_addr = current_state->VG_INSTR_PTR;
    res = DISASM_TO_IR(irsb, (const UChar *)inst_addr, 0, inst_addr, guest_arch,
                       &guest_arch_info, &abi_info, guest_arch_info.endness,
                       False);
    if (res.len == 0) {
      VG_(printf)("Could not disassemble 0x%lx!\n", inst_addr);
      continue;
    }

    VG_(printf)("0x%lx:\n", inst_addr);
    ppIRSB(irsb);
    VG_(printf)("\n");
  }
}

/**
 * @brief Recovers pointer input structures in case of a segfault
 * @param sigNo
 * @param addr
 */
static void SE_(signal_handler)(Int sigNo, Addr addr) {
  if (client_running && target_called) {
    if (sigNo == VKI_SIGSEGV && SE_(command_server)->using_fuzzed_io_vec) {
      fix_address_space(addr);
      SE_(write_io_vec_to_fd)
      (SE_(command_server)->executor_pipe[1], SEMSG_NEW_ALLOC,
       SE_(current_io_vec));
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

    if (SE_(command_server)->current_state != SERVER_EXECUTING) {
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
static void SE_(report_success_to_commader)(void) {
  tl_assert(client_running);
  tl_assert(main_replaced);

  if (SE_(command_server)->using_fuzzed_io_vec) {
    SE_(send_fuzzed_io_vec)();
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
    return;
  }

  VG_(umsg)("Setting program state\n");

  VexGuestArchState current_state;
  VG_(get_shadow_regs_area)
  (target_id, (UChar *)&current_state, 0, 0, sizeof(current_state));

#if defined(VGA_amd64)
  VG_(umsg)
  ("About to execute 0x%lx with RDI = 0x%llx\n", VG_(get_IP)(target_id),
   SE_(current_io_vec)->initial_state.guest_RDI);
  current_state.guest_RDI = SE_(current_io_vec)->initial_state.guest_RDI;
#endif
  VG_(set_shadow_regs_area)
  (target_id, 0, 0, sizeof(SE_(current_io_vec)->expected_state),
   (UChar *)&current_state);
  target_called = True;
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
    VG_(umsg)("Recording state for 0x%lx\n", VG_(get_IP)(target_id));
    VexGuestArchState current_state;
    VG_(get_shadow_regs_area)
    (target_id, (UChar *)&current_state, 0, 0, sizeof(current_state));
    VG_(addToXA)(program_states, &current_state);
  }
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

  for (/* use current i */; i < bb->stmts_used; i++) {
    IRStmt *stmt = bb->stmts[i];
    if (!stmt)
      continue;

    if (VG_(strcmp)(fnname, target_name) == 0 && i == bb->stmts_used - 1 &&
        bb->jumpkind == Ijk_Ret) {
      di = unsafeIRDirty_0_N(
          0, "report_success_to_commader",
          VG_(fnptr_to_fnentry)(&SE_(report_success_to_commader)),
          mkIRExprVec_0());
      addStmtToIRSB(bbOut, IRStmt_Dirty(di));
      continue;
    }
    switch (stmt->tag) {
    case Ist_IMark:
      if (minAddress == 0) {
        minAddress = (UWord)stmt->Ist.IMark.addr;
      }
      if (stmt->Ist.IMark.addr > maxAddress) {
        maxAddress = (UWord)stmt->Ist.IMark.addr;
      }
      addStmtToIRSB(bbOut, stmt);
      if (stmt->Ist.IMark.addr == SE_(command_server)->target_func_addr) {
        di = unsafeIRDirty_0_N(0, "jump_to_target_function",
                               VG_(fnptr_to_fnentry)(&jump_to_target_function),
                               mkIRExprVec_0());
        addStmtToIRSB(bbOut, IRStmt_Dirty(di));
      } else {
        di = unsafeIRDirty_0_N(0, "record_current_state",
                               VG_(fnptr_to_fnentry)(&record_current_state),
                               mkIRExprVec_0());
        addStmtToIRSB(bbOut, IRStmt_Dirty(di));
      }
      break;
    case Ist_Exit:
      if (VG_(strcmp)(fnname, target_name) == 0 && bb->jumpkind != Ijk_Boring) {
        di = unsafeIRDirty_0_N(
            0, "report_success_to_commader",
            VG_(fnptr_to_fnentry)(&SE_(report_success_to_commader)),
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

  UWord keyMin, keyMax, val;
  VG_(lookupRangeMap)(&keyMin, &keyMax, &val, irsb_ranges, minAddress);
  if (val == 0) {
    VG_(bindRangeMap)(irsb_ranges, minAddress, maxAddress, minAddress);
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
