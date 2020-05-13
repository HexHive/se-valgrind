//
// Created by derrick on 3/4/20.
//

#include "pub_tool_options.h"
#include "segrind_tool.h"

UInt SE_(MaxDuration) = DEFAULT_DURATION;
Int SE_(cmd_in) = -1;
Int SE_(cmd_out) = -1;
Int SE_(log) = -1;
Addr SE_(user_main) = 0;
UInt SE_(MaxAttempts) = DEFAULT_ATTEMPTS;
ULong SE_(MaxInstructions) = DEFAULT_MAX_INSTR;

Bool SE_(process_cmd_line_option)(const HChar *arg) {
  const HChar *tmp_str;

  if (VG_STR_CLO(arg, "--in-pipe", tmp_str)) {
    VG_(umsg)("Opening %s\n", tmp_str);
    if ((SE_(cmd_in) = VG_(fd_open)(tmp_str, VKI_O_RDONLY, 0)) < 0) {
      VG_(fmsg_bad_option(arg, "Could not open in-pipe\n"));
    }
  } else if (VG_STR_CLO(arg, "--out-pipe", tmp_str)) {
    VG_(umsg)("Opening %s\n", tmp_str);
    if ((SE_(cmd_out) = VG_(fd_open)(tmp_str, VKI_O_WRONLY, 0)) < 0) {
      VG_(fmsg_bad_option(arg, "Could not open out-pipe\n"));
    }
  } else if (VG_STR_CLO(arg, "--log", tmp_str)) {
    VG_(umsg)("Opening %s\n", tmp_str);
    if ((SE_(log) = VG_(fd_open)(tmp_str, VKI_O_WRONLY, 0)) < 0) {
      VG_(fmsg_bad_option(arg, "Could not open log\n"));
    }
  } else if (VG_INT_CLO(arg, "--max-duration", SE_(MaxDuration))) {
    if (SE_(MaxDuration) <= 0) {
      VG_(fmsg_bad_option(arg, "max-duration must be larger than zero"));
    }
  } else if (VG_INT_CLO(arg, "--main-addr", SE_(user_main))) {
    if (SE_(user_main) <= 0) {
      VG_(fmsg_bad_option(arg, "Invalid main address"));
    }
  } else if (VG_INT_CLO(arg, "--seed", SE_(seed))) {
  } else if (VG_INT_CLO(arg, "--max-attempts", SE_(MaxAttempts))) {
    if (SE_(MaxAttempts) > WARN_ATTEMPTS) {
      VG_(umsg)("Warning! High Attempt Count %u\n!", SE_(MaxAttempts));
    }
  } else if (VG_INT_CLO(arg, "--max-inst", SE_(MaxInstructions))) {
  }

  return False;
}

void SE_(print_usage)(void) {
  VG_(printf)
  ("--in-pipe=<file>             Filename of the command server read pipe\n"
   "--out-pipe=<file>            Filename of the command server write pipe\n"
   "--log=<file>                 Filename of the log to write to\n"
   "--max-duration=<millis>      Max number of milliseconds to run before "
   "executor process is killed. Defaults to %u\n"
   "--max-attempts=<int>         Max number of attempts at trying to fuzz a "
   "function before giving up. Defaults to %u\n"
   "--main-addr=<addr>           The location of main\n"
   "--seed=<int>                 The initial seed to use\n"
   "--max-inst=<int>             Max number of instructions to execute before "
   "executor process quits. Defaults to %llu\n",
   DEFAULT_DURATION, DEFAULT_ATTEMPTS, DEFAULT_MAX_INSTR);
}

void SE_(print_debug_usage)(void) { SE_(print_usage)(); }

void SE_(set_clo_defaults)(void) {
  SE_(cmd_in) = -1;
  SE_(cmd_out) = -1;
  SE_(log) = -1;
}
