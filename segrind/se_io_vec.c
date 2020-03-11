//
// Created by derrick on 3/10/20.
//

#include "se_io_vec.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"
#include "se_command.h"

const HChar *SE_IOVEC_MALLOC_TYPE = "SE_(io_vec)";

SE_(io_vec) * SE_(create_io_vec)(void) {
  SE_(io_vec) *io_vec =
      (SE_(io_vec) *)VG_(malloc)(SE_IOVEC_MALLOC_TYPE, sizeof(SE_(io_vec)));
  tl_assert(io_vec);

  VexArchInfo arch_info;
  VG_(machine_get_VexArchInfo)(&io_vec->host_arch, &arch_info);
  io_vec->host_endness = arch_info.endness;

  io_vec->system_calls =
      VG_(OSetWord_Create)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free));

  return io_vec;
}

void SE_(free_io_vec)(SE_(io_vec) * io_vec) {
  tl_assert(io_vec);
  VG_(OSetWord_Destroy)(io_vec->system_calls);
  VG_(free)(io_vec);
}

SizeT SE_(write_io_vec_to_fd)(Int fd, SE_(io_vec) * io_vec) {
  tl_assert(fd > 0);
  tl_assert(io_vec);
  HChar *data =
      (HChar *)VG_(malloc)(SE_IOVEC_MALLOC_TYPE, SE_(io_vec_size)(io_vec));

  SizeT bytes_written = 0;
  VG_(memcpy)(data, &io_vec->host_arch, sizeof(io_vec->host_arch));
  bytes_written += sizeof(io_vec->host_arch);

  VG_(memcpy)
  (data + bytes_written - 1, &io_vec->host_endness,
   sizeof(io_vec->host_endness));
  bytes_written += sizeof(io_vec->host_endness);

  VG_(memcpy)
  (data + bytes_written - 1, &io_vec->initial_state,
   sizeof(io_vec->initial_state));
  bytes_written += sizeof(io_vec->initial_state);

  VG_(memcpy)
  (data + bytes_written - 1, &io_vec->expected_state,
   sizeof(io_vec->expected_state));
  bytes_written += sizeof(io_vec->expected_state);

  Word syscall_count = VG_(OSetWord_Size)(io_vec->system_calls);
  VG_(memcpy)(data + bytes_written, &syscall_count, sizeof(syscall_count));
  bytes_written += sizeof(syscall_count);

  UWord syscall_num;
  while (VG_(OSetWord_Next)(io_vec->system_calls, &syscall_num)) {
    VG_(memcpy)(data + bytes_written - 1, &syscall_num, sizeof(syscall_num));
    bytes_written += sizeof(syscall_num);
  }

  VG_(OSetWord_ResetIter)(io_vec->system_calls);

  SE_(cmd_msg) *cmd_msg = SE_(create_cmd_msg)(SEMSG_OK, bytes_written, data);
  bytes_written = SE_(write_msg_to_fd)(fd, cmd_msg);
  VG_(free)(data);
  SE_(free_msg)(cmd_msg);

  return bytes_written;
}

SizeT SE_(io_vec_size)(SE_(io_vec) * io_vec) {
  tl_assert(io_vec);

  return (sizeof(VexArch)                 /* Architecture type */
          + sizeof(VexEndness)            /* Endness */
          + 2 * sizeof(VexGuestArchState) /* The initial and expected states */
          + sizeof(Word)                  /* System call count */
          + VG_(OSetWord_Size)(io_vec->system_calls) *
                sizeof(UWord) /* System calls */
  );
}