//
// Created by derrick on 3/24/20.
//

#ifndef SE_VALGRIND_SE_TAINT_H
#define SE_VALGRIND_SE_TAINT_H

#include "segrind_tool.h"

#include "libvex_ir.h"
#include "pub_tool_oset.h"
#include "pub_tool_xarray.h"

#define SE_DEFAULT_ALLOC_SPACE sizeof(Addr)

typedef enum {
  taint_invalid = -1,
  taint_addr, /* A guest memory location */
  taint_reg,  /* A guest register */
  taint_temp, /* An IRSB temporary */
  taint_stack /* A guest stack location */
} TaintType;

/**
 * @brief A tainted location
 */
typedef struct se_tainted_location {
  TaintType type;
  union {
    Addr addr;   /* The tainted address */
    Int offset;  /* The reg represented by offset in the VexGuestArchState */
    IRTemp temp; /* The IRSB temporary */
  } location;
} SE_(tainted_loc);

typedef struct se_taint_info_ {
  SE_(tainted_loc) taint_source; /* The source of the faulting address */
  Addr faulting_address;         /* The address which caused the fault */
} SE_(taint_info);

/**
 * @brief Compares two tainted locations
 * @param key
 * @param elem
 * @return
 */
Word SE_(taint_cmp)(const void *key, const void *elem);

/**
 * @brief Start taint analysis
 * @param program_states
 * @param the faulting_address
 */
void SE_(init_taint_analysis)(XArray *program_states, Addr addr);

/**
 * @brief Frees resources allocated for taint analysis
 */
void SE_(end_taint_analysis)(void);

/**
 * @brief Get the underlying register or temporary
 * @param expr
 * @return
 */
IRExpr *SE_(get_IRExpr)(IRExpr *expr);

/**
 * @brief Removes any taint associated with this IRExpr
 * @param irExpr
 * @param idx - Current program state index
 */
void SE_(remove_IRExpr_taint)(IRExpr *irExpr, Word idx);

/**
 * @brief Taints any location associated with this IRExpr
 * @param irExpr
 * @param idx - Current program state index
 */
void SE_(taint_IRExpr)(IRExpr *irExpr, Word idx);

/**
 * @brief Checks if any location associated with this IRExpr is tainted
 * @param irExpr
 * @param idx - Current program state index
 * @return
 */
Bool SE_(is_IRExpr_tainted)(IRExpr *irExpr, Word idx);

/**
 * @brief Prints out information regarding the tainted location
 * @param loc
 */
void SE_(ppTaintedLocation)(const SE_(tainted_loc) * loc);

/**
 * @brief Returns the tainted locations
 * @return
 */
OSet *SE_(get_tainted_locations)(void);

/**
 * @brief Returns True if taint has been found
 * @return
 */
Bool SE_(taint_found)(void);

/**
 * @brief Checks if the specified register is tainted
 * @param offset
 * @return
 */
Bool SE_(guest_reg_tainted)(Int offset);

/**
 * @brief Removes taint from a register
 * @param offset
 */
void SE_(remove_tainted_reg)(Int offset);

/**
 * @brief Returns True if the temporary is temporary
 * @param temp
 * @return
 */
Bool SE_(temp_tainted)(IRTemp temp);

/**
 * @brief Taints the temporary variable
 * @param temp
 */
void SE_(taint_temp)(IRTemp temp);

/**
 * @brief Removes taint from temporary
 * @param tmp
 */
void SE_(remove_tainted_temp)(IRTemp tmp);

/**
 * @brief Removes temporaries from the list
 */
void SE_(clear_temps)(void);

/**
 * @brief Returns True if the IRExpr contains an Iex_Load
 * @param irExpr
 * @return
 */
Bool SE_(IRExpr_contains_load)(const IRExpr *irExpr);

/**
 * @brief Returns the first tainted address location, or NULL if there isn't any
 * @return
 */
const SE_(taint_info) * SE_(get_taint_info)(void);

#endif // SE_VALGRIND_SE_TAINT_H
