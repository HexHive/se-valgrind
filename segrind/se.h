//
// Created by derrick on 3/4/20.
//

#ifndef FOSBIN_SE_H
#define FOSBIN_SE_H

#include "pub_tool_basics.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_machine.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_vki.h"

#define SE_(str) VGAPPEND(vgSegrind_, str)

Int SE_(internal_pipe_in)[2];
Int SE_(internal_pipe_out)[2];

Int SE_(cmd_in), SE_(cmd_out), SE_(log);

/*****************************************************
 * Command line parsing
 *****************************************************/
Bool SE_(process_cmd_line_option)(const HChar *argv);
void SE_(print_usage)(void);
void SE_(print_debug_usage)(void);
void SE_(set_clo_defaults)(void);

#endif //FOSBIN_SE_H
