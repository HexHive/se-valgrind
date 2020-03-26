//
// Created by derrick on 3/10/20.
//

#ifndef SE_VALGRIND_SE_IO_VEC_H
#define SE_VALGRIND_SE_IO_VEC_H

#include "libvex.h"
#include "pub_tool_guest.h"
#include "pub_tool_oset.h"
#include "pub_tool_rangemap.h"
#include "se.h"
#include "se_command.h"
#include "se_taint.h"

const HChar *SE_IOVEC_MALLOC_TYPE;

#define ALLOCATED_SUBPTR_MAGIC 0xA110CA7E
#define OBJ_START_MAGIC 0xA110CA57
#define OBJ_END_MAGIC 0xA110CAED

typedef struct se_program_state_ {
  VexGuestArchState register_state;
  RangeMap *address_state;
} SE_(program_state);

typedef struct io_vec {
  VexArch host_arch;
  VexEndness host_endness;
  UInt random_seed;

  SE_(program_state) initial_state;
  SE_(program_state) expected_state;

  OSet *system_calls;
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

#endif // SE_VALGRIND_SE_IO_VEC_H
