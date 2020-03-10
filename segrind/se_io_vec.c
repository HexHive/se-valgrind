//
// Created by derrick on 3/10/20.
//

#include "se_io_vec.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"

const HChar *SE_IOVEC_MALLOC_TYPE = "SE_(io_vec)";

SE_(io_vec) * SE_(create_iovec)(void) {
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

void SE_(free_iovec)(SE_(io_vec) * io_vec) {
  tl_assert(io_vec);
  VG_(OSetWord_Destroy)(io_vec->system_calls);
  VG_(free)(io_vec);
}

SizeT SE_(write_io_vec_to_fd)(Int fd, SE_(io_vec) * io_vec) {
  tl_assert(fd > 0);
  tl_assert(io_vec);

  SizeT bytes_written = 0;
  if (VG_(write)(fd, &io_vec->host_arch, sizeof(io_vec->host_arch)) <= 0) {
    return 0;
  }
  bytes_written += sizeof(io_vec->host_arch);

  if (VG_(write)(fd, &io_vec->host_endness, sizeof(io_vec->host_endness)) <=
      0) {
    return 0;
  }
  bytes_written += sizeof(io_vec->host_endness);

  if (VG_(write)(fd, &io_vec->initial_state, sizeof(io_vec->initial_state)) <=
      0) {
    return 0;
  }
  bytes_written += sizeof(io_vec->initial_state);

  if (VG_(write)(fd, &io_vec->expected_state, sizeof(io_vec->expected_state)) <=
      0) {
    return 0;
  }
  bytes_written += sizeof(io_vec->expected_state);

  UWord syscall_num;
  Word syscall_count = VG_(OSetWord_Size)(io_vec->system_calls);
  if (VG_(write)(fd, &syscall_count, sizeof(syscall_count)) <= 0) {
    return 0;
  }
  bytes_written += sizeof(syscall_count);

  for (; VG_(OSetWord_Next)(io_vec->system_calls, &syscall_num);) {
    if (VG_(write)(fd, &syscall_num, sizeof(syscall_num)) <= 0) {
      VG_(OSetWord_ResetIter)(io_vec->system_calls);
      return 0;
    }
    bytes_written += sizeof(syscall_num);
  }

  VG_(OSetWord_ResetIter)(io_vec->system_calls);
  return bytes_written;
}