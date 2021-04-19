//
// Created by derrick on 3/10/20.
//

#ifndef SE_VALGRIND_SE_IO_VEC_H
#define SE_VALGRIND_SE_IO_VEC_H

#include "libvex.h"
#include "pub_tool_guest.h"
#include "pub_tool_oset.h"
#include "pub_tool_rangemap.h"
#include "pub_tool_xarray.h"
#include "se_command.h"
#include "se_taint.h"
#include "segrind_tool.h"

extern const HChar *SE_IOVEC_MALLOC_TYPE;

#define ALLOCATED_SUBPTR_MAGIC 0b00000001
#define OBJ_START_MAGIC 0b00000010
#define OBJ_END_MAGIC 0b00000100
#define OBJ_ALLOCATED_MAGIC 0b00001000

/**
 * @brief The relevant program state stored in IOVecs
 */
typedef struct se_program_state_ {
    XArray *register_state;  /* Register values */
    RangeMap *address_state; /* Object layout */
    RangeMap
            *pointer_member_locations; /* Location and value of pointer submembers */
} SE_(program_state);

/**
 * @brief The return value of the function
 */
typedef struct se_return_value_ {
    SE_(memoized_object) value;
    Bool is_ptr;
} SE_(return_value);

/**
 * @brief A register value and whether it is a pointer
 */
typedef struct se_register_value_ {
    Int guest_state_offset;
    RegWord value;
    Bool is_ptr;
} SE_(register_value);

/**
 * @brief The main IOVec object that segrind uses for analysis
 */
typedef struct io_vec {
    VexArch host_arch;       /* Architecture that generated this IOVec */
    VexEndness host_endness; /* Endianess of generation machine */
    UInt random_seed;        /* Random seed used to fuzz this IOVec */

    SE_(program_state) initial_state; /* Initial program state */
    RangeMap *expected_state;         /* State expected post-execution */

    SE_(return_value) return_value; /* The expected return value */

    OSet *system_calls; /* Unique set of system calls executed */
} SE_(io_vec);

/**
 * @brief Allocates a new io_vec which must be later freed. Always returns valid
 * io_vec.
 * @return
 */
SE_(io_vec) * SE_(create_io_vec)(void);
void SE_(free_io_vec)(SE_(io_vec) * io_vec);

/**
 * @brief Writes io_vec to specified file descriptor
 * @param fd
 * @param msg_type
 * @param io_vec
 * @return bytes written or 0 on error
 */
SizeT SE_(write_io_vec_to_fd)(Int fd, SE_(cmd_msg_t) msg_type,
                              SE_(io_vec) * io_vec);

/**
 * @brief Computes the number of bytes io_vec will write to a file descriptor
 * @param io_vec
 * @return
 */
SizeT SE_(io_vec_size)(SE_(io_vec) * io_vec);

/**
 * @brief Reads an IOVec from the specified file descriptor
 * @param fd
 * @return IOVec or NULL on error
 */
SE_(io_vec) * SE_(read_io_vec_from_fd)(Int fd);

/**
 * @brief Creates an IOVec from src
 * @param dest
 * @param len
 * @param src
 */
SE_(io_vec) * SE_(read_io_vec_from_buf)(SizeT len, UChar *src);

/**
 * @brief Memoizes an IOVec into a memory buffer
 * @param io_vec
 * @param dest
 * @return
 */
void SE_(write_io_vec_to_buf)(SE_(io_vec) * io_vec,
                              SE_(memoized_object) * dest);

/**
 * @brief Prints the IOVec using printf
 * @param io_vec
 */
void SE_(ppIOVec)(SE_(io_vec) * io_vec);

/**
 * @brief Prints the program state using printf
 * @param program_state
 */
void SE_(ppProgramState)(SE_(program_state) * program_state);

/**
 * @brief Returns true if the current program state matches the expected state
 * @param io_vec
 * @param return_value
 * @param syscalls
 * @return
 */
Bool SE_(current_state_matches_expected)(SE_(io_vec) * io_vec,
                                         SE_(return_value) * return_value,
                                         OSet *syscalls);

/**
 * @brief Returns True if the two return values match our return value heuristic
 * @param rv_1
 * @param rv_2
 * @return
 */
Bool SE_(return_values_same)(SE_(return_value) * rv_1,
                             SE_(return_value) * rv_2);

/**
 * @brief Translates an IOVec from its originating architecture to the current
 * host architecture
 * @param original
 * @param host_io_vec
 * @return True on success, False otherwise
 */
Bool SE_(translate_io_vec_to_host)(SE_(io_vec) * original,
                                   SE_(io_vec) * host_io_vec);

#endif // SE_VALGRIND_SE_IO_VEC_H
