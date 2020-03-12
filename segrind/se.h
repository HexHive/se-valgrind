//
// Created by derrick on 3/4/20.
//

#ifndef FOSBIN_SE_H
#define FOSBIN_SE_H

#define SE_(str) VGAPPEND(vgSegrind_, str)

#define MAX_DURATION ((UInt)10000)

#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_machine.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_vki.h"

Int SE_(cmd_in), SE_(cmd_out), SE_(log);

/* Number of milliseconds to run a function for */
UInt SE_(MaxDuration);

Addr SE_(user_main);

/*****************************************************
 * Command line parsing
 *****************************************************/
Bool SE_(process_cmd_line_option)(const HChar *argv);
void SE_(print_usage)(void);
void SE_(print_debug_usage)(void);
void SE_(set_clo_defaults)(void);

#endif // FOSBIN_SE_H
