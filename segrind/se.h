//
// Created by derrick on 3/4/20.
//

#ifndef FOSBIN_SE_H
#define FOSBIN_SE_H

#define SE_(str) VGAPPEND(vgSegrind_, str)

#define DEFAULT_DURATION ((UInt)10000)
#define DEFAULT_ATTEMPTS ((UInt)25)
#define WARN_ATTEMPTS 10

#define SE_TOOL_ALLOC_STR "segrind"

#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_machine.h"
#include "pub_tool_oset.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_vki.h"
#include "se_defs.h"

Int SE_(cmd_in), SE_(cmd_out), SE_(log);

/* Number of milliseconds to run a function for */
UInt SE_(MaxDuration);

Addr SE_(user_main);

UInt SE_(seed);

UInt SE_(MaxAttempts);

/*****************************************************
 * Command line parsing
 *****************************************************/
Bool SE_(process_cmd_line_option)(const HChar *argv);
void SE_(print_usage)(void);
void SE_(print_debug_usage)(void);
void SE_(set_clo_defaults)(void);

/*****************************************************
 * Utilities
 *****************************************************/
/**
 * @brief Copies an OSetWord size and data into allocated memory buffer
 * @param oset
 * @param dest - Where to write the location of the allocated memory buffer
 * @return Size of the allocated buffer
 */
SizeT SE_(Memoize_OSetWord)(OSet *oset, UChar **dest);

#endif // FOSBIN_SE_H
