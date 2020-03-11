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

#include "pub_tool_basics.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_oset.h"

static Bool client_running = False;
static ThreadId target_id = VG_INVALID_THREADID;
static SE_(cmd_server) * SE_(command_server) = NULL;
static OSet *syscalls = NULL;
static OSet *coverage = NULL;
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
    SE_(start_server)(SE_(command_server));

    if (SE_(command_server)->current_state != SERVER_EXECUTING) {
      VG_(exit)(0);
    }

    /* Child executors arrive here */
    VG_(set_IP)(target_id, SE_(command_server)->target_func_addr);
    syscalls =
        VG_(OSetWord_Create)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free));
    if (SE_(command_server)->using_fuzzed_io_vec) {
      if (fuzzed_io_vec) {
        SE_(free_io_vec)(fuzzed_io_vec);
      }
      fuzzed_io_vec = SE_(create_io_vec)();
      VG_(get_shadow_regs_area)
      (target_id, (UChar *)&fuzzed_io_vec->initial_state, 0, 0,
       sizeof(fuzzed_io_vec->initial_state));
    }
  }
}

static void SE_(thread_exit)(ThreadId tid) {
  if (client_running && tid == target_id) {
    client_running = False;
    target_id = VG_INVALID_THREADID;
    if (SE_(command_server)->using_fuzzed_io_vec) {
      SE_(send_fuzzed_io_vec)();
    }
  }
}

static void SE_(start_client_code)(ThreadId tid, ULong blocks_dispatched) {
  if (!client_running && tid == target_id) {
    client_running = True;
  }
}

static IRSB *SE_(instrument)(VgCallbackClosure *closure, IRSB *bb,
                             const VexGuestLayout *layout,
                             const VexGuestExtents *vge,
                             const VexArchInfo *archinfo_host, IRType gWordTy,
                             IRType hWordTy) {
  DiEpoch de = VG_(current_DiEpoch)();
  const HChar *fnname;
  VG_(get_fnname)(de, closure->nraddr, &fnname);
  VG_(umsg)
  ("(PID %d TID %d)\tThread %u (IP = 0x%lx) requested translation of block "
   "starting at 0x%lx (0x%lx) in function "
   "%s\n",
   VG_(getpid)(), VG_(gettid)(), closure->tid, VG_(get_IP)(closure->tid),
   closure->nraddr, closure->readdr, fnname);
  return bb;
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
