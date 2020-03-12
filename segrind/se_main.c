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
#include "se_io_vec.h"
#include <libvex_ir.h>

#include "pub_tool_basics.h"
#include "pub_tool_guest.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_oset.h"
#include "pub_tool_xarray.h"

static Bool client_running = False;
static Bool main_replaced = False;
static ThreadId target_id = VG_INVALID_THREADID;
static SE_(cmd_server) * SE_(command_server) = NULL;
static OSet *syscalls = NULL;
static XArray *program_states = NULL;
static SE_(io_vec) *fuzzed_io_vec = NULL;

static SizeT SE_(write_io_vec_to_cmd_server)(SE_(io_vec) * io_vec,
                                             Bool free_io_vec) {
  tl_assert(SE_(command_server));
  tl_assert(io_vec);

  SizeT bytes_written =
      SE_(write_io_vec_to_fd)(SE_(command_server)->executor_pipe[1], io_vec);

  if (free_io_vec) {
    SE_(free_io_vec)(io_vec);
  }
  return bytes_written;
}

static void SE_(send_fuzzed_io_vec)(void) {
  UWord syscall_num;
  while (VG_(OSetWord_Next)(syscalls, &syscall_num)) {
    VG_(OSetWord_Insert)(fuzzed_io_vec->system_calls, syscall_num);
  }
  VG_(get_shadow_regs_area)
  (target_id, (UChar *)&fuzzed_io_vec->expected_state, 0, 0,
   sizeof(fuzzed_io_vec->expected_state));

  tl_assert(SE_(write_io_vec_to_cmd_server)(fuzzed_io_vec, True) > 0);
}

static void SE_(post_clo_init)(void) {
  SE_(command_server) = SE_(make_server)(SE_(cmd_in), SE_(cmd_out));
  tl_assert(SE_(command_server));
}

static void SE_(thread_creation)(ThreadId tid, ThreadId child) {
  if (!client_running) {
    target_id = child;
    VG_(umsg)("Starting Command Server\n");
    SE_(start_server)(SE_(command_server), child);

    if (SE_(command_server)->current_state != SERVER_EXECUTING) {
      VG_(exit)(0);
    }

    /* Child executors arrive here */
    syscalls =
        VG_(OSetWord_Create)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free));
    program_states = VG_(newXA)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free),
                                sizeof(VexGuestArchState));
    if (SE_(command_server)->using_fuzzed_io_vec) {
      if (fuzzed_io_vec) {
        SE_(free_io_vec)(fuzzed_io_vec);
      }
      fuzzed_io_vec = SE_(create_io_vec)();
      VG_(get_shadow_regs_area)
      (target_id, (UChar *)&fuzzed_io_vec->initial_state, 0, 0,
       sizeof(fuzzed_io_vec->initial_state));
    }
#if defined(VGA_amd64)
    VG_(umsg)
    ("About to execute 0x%lx with RDI = 0x%llx\n", VG_(get_IP)(target_id),
     fuzzed_io_vec->initial_state.guest_RDI);
#endif
  }
}

static void SE_(thread_exit)(ThreadId tid) {
  if (client_running && tid == target_id) {
    client_running = False;
    main_replaced = False;
    target_id = VG_INVALID_THREADID;
    if (SE_(command_server)->using_fuzzed_io_vec) {
      SE_(send_fuzzed_io_vec)();
    }

    VG_(deleteXA)(program_states);
    program_states = NULL;
    VG_(OSetWord_Destroy)(syscalls);
    syscalls = NULL;
  }
}

static void SE_(start_client_code)(ThreadId tid, ULong blocks_dispatched) {
  if (!client_running && tid == target_id) {
    client_running = True;
  }
}

static void record_current_state(void) {
  if (client_running && main_replaced) {
    VexGuestArchState current_state;
    VG_(get_shadow_regs_area)
    (target_id, (UChar *)&current_state, 0, 0, sizeof(current_state));
    const HChar *fnname;
    VG_(get_fnname)(VG_(current_DiEpoch)(), VG_(get_IP)(target_id), &fnname);
    VG_(umsg)
    ("\tRecording state for instruction at 0x%lx (%s)\n",
     VG_(get_IP)(target_id), fnname);
    VG_(addToXA)(program_states, &current_state);
  }
}

static IRSB *SE_(instrument_target)(IRSB *bb) {
  tl_assert(client_running);
  tl_assert(main_replaced);

  IRSB *bbOut;
  Int i;
  IRDirty *di;

  bbOut = deepCopyIRSBExceptStmts(bb);

  i = 0;
  while (i < bb->stmts_used && bb->stmts[i]->tag != Ist_IMark) {
    addStmtToIRSB(bbOut, bb->stmts[i]);
  }

  for (/* use current i */; i < bb->stmts_used; i++) {
    IRStmt *stmt = bb->stmts[i];
    if (!stmt)
      continue;

    switch (stmt->tag) {
    case Ist_IMark:
      di = unsafeIRDirty_0_N(0, "record_current_state",
                             VG_(fnptr_to_fnentry)(&record_current_state),
                             mkIRExprVec_0());
      addStmtToIRSB(bbOut, stmt);
      addStmtToIRSB(bbOut, IRStmt_Dirty(di));
      break;
    default:
      addStmtToIRSB(bbOut, stmt);
      break;
    }
  }
  return bbOut;
}

static IRSB *SE_(replace_main_if_found)(IRSB *bb) {
  tl_assert(client_running);
  tl_assert(!main_replaced);

  IRSB *bbOut = bb;
  IRConst *new_dst;
  IRExpr *new_guard;
  Int i;

  IRJumpKind bb_jump = bb->jumpkind;
  if (bb_jump == Ijk_Call) {
    bbOut = deepCopyIRSBExceptStmts(bb);
    i = 0;
    while (i < bb->stmts_used && bb->stmts[i]->tag != Ist_IMark) {
      addStmtToIRSB(bbOut, bb->stmts[i]);
    }

    for (/* use current i */; i < bb->stmts_used; i++) {
      IRStmt *stmt = bb->stmts[i];
      if (!stmt)
        continue;

      switch (stmt->tag) {
      case Ist_Exit:
        VG_(umsg)("Exit dst: %llx\n", stmt->Ist.Exit.dst->Ico.U64);
        if (stmt->Ist.Exit.dst->Ico.U64 == SE_(command_server)->main_addr) {
          VG_(umsg)("Replacing main!\n");
          new_dst = IRConst_U64((ULong)SE_(command_server)->target_func_addr);
          new_guard = deepCopyIRExpr(stmt->Ist.Exit.guard);
          stmt =
              IRStmt_Exit(new_guard, bb_jump, new_dst, stmt->Ist.Exit.offsIP);
          addStmtToIRSB(bbOut, stmt);
        } else {
          addStmtToIRSB(bbOut, stmt);
        }
        break;
      default:
        addStmtToIRSB(bbOut, stmt);
        break;
      }
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
  } else if (client_running && !main_replaced) {
    bbOut = SE_(replace_main_if_found)(bb);
  }

  if (!main_replaced &&
      VG_(get_IP)(target_id) == SE_(command_server)->main_addr) {
    ppIRSB(prev);
    ppIRSB(bbOut);
    tl_assert2(0, "ERROR: Reached main and it was not replaced!\n");
  }

  return bbOut;
}

static void SE_(pre_syscall)(ThreadId tid, UInt syscallno, UWord *args,
                             UInt nArgs) {
  if (tid == target_id && client_running &&
      !VG_(OSetWord_Contains)(syscalls, (UWord)syscallno)) {
    VG_(OSetWord_Insert)(syscalls, (UWord)syscallno);
  }
}

static void SE_(post_syscall)(ThreadId tid, UInt syscallno, UWord *args,
                              UInt nArgs, SysRes res) {}

static void SE_(fini)(Int exitcode) {
  if (SE_(cmd_in) > 0) {
    VG_(close)(SE_(cmd_in));
  }

  if (SE_(cmd_out) > 0) {
    VG_(close)(SE_(cmd_out));
  }

  if (SE_(log) > 0) {
    VG_(close)(SE_(log));
  }

  if (SE_(command_server)) {
    SE_(free_server)(SE_(command_server));
  }
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

  SE_(set_clo_defaults)();
}

VG_DETERMINE_INTERFACE_VERSION(SE_(pre_clo_init))

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
