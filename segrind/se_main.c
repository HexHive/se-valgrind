
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

#include "../coregrind/pub_core_threadstate.h"
#include "pub_tool_basics.h"
#include "pub_tool_options.h"
         "
#include "se.h"
#include "valgrind.h"

static Bool client_running = False;
static ThreadId target_id = VG_INVALID_THREADID;

#define INSTR_PTR(regs) ((regs).vex.VG_INSTR_PTR)

extern VG_(set_IP)(ThreadId tid, Addr addr);

static void SE_(post_clo_init)(void) {
  VG_(clo_vex_control).iropt_register_updates_default =
      VexRegUpdAllregsAtEachInsn;
}

static void SE_(thread_creation)(ThreadId tid, ThreadId child) {
  if (!client_running) {
    VG_(umsg)("Thread %u created target thread %u\n", tid, child);
    target_id = child;
  }
}

static void SE_(thread_exit)(ThreadId tid) {
  if (client_running && tid == target_id) {
    VG_(umsg)("Thread %u has exited\n", tid);
    client_running = False;
    target_id = VG_INVALID_THREADID;
  }
}

static void SE_(start_client_code)(ThreadId tid, ULong blocks_dispatched) {
  if (!client_running && tid == target_id) {
    VG_(umsg)
    ("Thread %u is starting executing at instruction 0x%lx with "
     "blocks_dispatched=%llu\n",
     tid, VG_(get_IP)(tid), blocks_dispatched);
    client_running = True;
    VG_(set_IP)(target_id, (Addr)0x10914B);
    VG_(umsg)("Thread %u IP = 0x%lx\n", target_id, VG_(get_IP)(target_id));
  }
}

static void SE_(stop_client_code)(ThreadId tid, ULong blocks_dispatched) {
  //    VG_(umsg)("Thread %u stopped executing at instruction 0x%lx with
  //    blocks_dispatched=%llu\n", tid, VG_(get_IP)(tid), blocks_dispatched);
}

static IRSB *SE_(instrument)(VgCallbackClosure *closure, IRSB *bb,
                             const VexGuestLayout *layout,
                             const VexGuestExtents *vge,
                             const VexArchInfo *archinfo_host, IRType gWordTy,
                             IRType hWordTy) {
  //    if(target_function_running) {
  DiEpoch de = VG_(current_DiEpoch)();
  const HChar *fnname;
  VG_(get_fnname)(de, closure->nraddr, &fnname);
  VG_(umsg)
  ("Thread %u requested translation of block starting at 0x%lx in function "
   "%s\n",
   closure->tid, closure->nraddr, fnname);
  //    }
  return bb;
}

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
  VG_(track_stop_client_code)(SE_(stop_client_code));
  VG_(track_pre_thread_ll_create)(SE_(thread_creation));
  VG_(track_pre_thread_ll_exit)(SE_(thread_exit));

  SE_(set_clo_defaults)();
}

VG_DETERMINE_INTERFACE_VERSION(SE_(pre_clo_init))

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
