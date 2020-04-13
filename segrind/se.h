//
// Created by derrick on 3/4/20.
//

#ifndef FOSBIN_SE_H
#define FOSBIN_SE_H

#define SE_(str) VGAPPEND(vgSegrind_, str)

#define DEFAULT_DURATION ((UInt)10000)
#define DEFAULT_ATTEMPTS ((UInt)25)
#define WARN_ATTEMPTS 10
#define DEFAULT_MAX_INSTR ((ULong)1000000UL)

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

/**
 * @brief Input/Output pipes and logfiles
 */
Int SE_(cmd_in), SE_(cmd_out), SE_(log);

/**
 * @brief Number of milliseconds to wait for a function to complete
 */
UInt SE_(MaxDuration);

/**
 * @brief Address of main function
 */
Addr SE_(user_main);

/**
 * @brief Random seed
 */
UInt SE_(seed);

/**
 * @brief Max attempts at executing a function before quitting
 */
UInt SE_(MaxAttempts);

/**
 * @brief Max number of instructions to execute per function execution
 */
ULong SE_(MaxInstructions);

typedef enum _memorized_obj_type {
  se_memo_invalid,
  se_memo_io_vec,
  se_memo_oset_word,
  se_memo_arch_state
} SE_(memoized_type);

typedef struct memoized_object {
  UChar *buf;
  SizeT len;
  SE_(memoized_type) type;
} SE_(memoized_object);

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
 */
void SE_(Memoize_OSetWord)(OSet *oset, SE_(memoized_object) * dest);

#endif // FOSBIN_SE_H
