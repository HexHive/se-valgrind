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

  VexArchInfo arch_info;
  VG_(machine_get_VexArchInfo)(&io_vec->host_arch, &arch_info);
  io_vec->host_endness = arch_info.endness;
  io_vec->random_seed = 0;

  io_vec->system_calls =
      VG_(OSetWord_Create)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free));

  io_vec->initial_state.address_state =
      VG_(newRangeMap)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free), 0);
  io_vec->expected_state.address_state =
      VG_(newRangeMap)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free), 0);

  return io_vec;
}

void SE_(free_io_vec)(SE_(io_vec) * io_vec) {
  tl_assert(io_vec);
  VG_(OSetWord_Destroy)(io_vec->system_calls);
  VG_(deleteRangeMap)(io_vec->initial_state.address_state);
  VG_(deleteRangeMap)(io_vec->expected_state.address_state);
  VG_(free)(io_vec);
}

SizeT SE_(write_io_vec_to_fd)(Int fd, SE_(cmd_msg_t) msg_type,
                              SE_(io_vec) * io_vec) {
  tl_assert(fd > 0);
  tl_assert(io_vec);
  HChar *data =
      (HChar *)VG_(malloc)(SE_IOVEC_MALLOC_TYPE, SE_(io_vec_size)(io_vec));

  SizeT bytes_written = 0;
  VG_(memcpy)(data, &io_vec->host_arch, sizeof(io_vec->host_arch));
  bytes_written += sizeof(io_vec->host_arch);

  VG_(memcpy)
  (data + bytes_written, &io_vec->host_endness, sizeof(io_vec->host_endness));
  bytes_written += sizeof(io_vec->host_endness);

  Word count = VG_(OSetWord_Size)(io_vec->system_calls);
  VG_(memcpy)(data + bytes_written, &count, sizeof(count));
  bytes_written += sizeof(count);

  UWord syscall_num;
  while (VG_(OSetWord_Next)(io_vec->system_calls, &syscall_num)) {
    VG_(memcpy)(data + bytes_written, &syscall_num, sizeof(syscall_num));
    bytes_written += sizeof(syscall_num);
  }

  VG_(memcpy)
  (data + bytes_written, &io_vec->random_seed, sizeof(io_vec->random_seed));
  bytes_written += sizeof(io_vec->random_seed);

  VG_(memcpy)
  (data + bytes_written, &io_vec->initial_state.register_state,
   sizeof(io_vec->initial_state.register_state));
  bytes_written += sizeof(io_vec->initial_state.register_state);

  UInt space_size = VG_(sizeRangeMap)(io_vec->initial_state.address_state);
  VG_(memcpy)(data + bytes_written, &space_size, sizeof(space_size));
  bytes_written += sizeof(space_size);
  for (UInt i = 0; i < space_size; i++) {
    UWord key_min, key_max, val;
    VG_(indexRangeMap)
    (&key_min, &key_max, &val, io_vec->initial_state.address_state, i);
    VG_(memcpy)(data + bytes_written, &key_min, sizeof(key_min));
    bytes_written += sizeof(key_min);
    VG_(memcpy)(data + bytes_written, &key_max, sizeof(key_max));
    bytes_written += sizeof(key_max);
    VG_(memcpy)(data + bytes_written, &val, sizeof(val));
    bytes_written += sizeof(val);
  }

  VG_(memcpy)
  (data + bytes_written, &io_vec->expected_state.register_state,
   sizeof(io_vec->expected_state.register_state));
  bytes_written += sizeof(io_vec->expected_state.register_state);

  space_size = VG_(sizeRangeMap)(io_vec->expected_state.address_state);
  VG_(memcpy)(data + bytes_written, &space_size, sizeof(space_size));
  bytes_written += sizeof(space_size);
  for (UInt i = 0; i < space_size; i++) {
    UWord key_min, key_max, val;
    VG_(indexRangeMap)
    (&key_min, &key_max, &val, io_vec->expected_state.address_state, i);
    VG_(memcpy)(data + bytes_written, &key_min, sizeof(key_min));
    bytes_written += sizeof(key_min);
    VG_(memcpy)(data + bytes_written, &key_max, sizeof(key_max));
    bytes_written += sizeof(key_max);
    VG_(memcpy)(data + bytes_written, &val, sizeof(val));
    bytes_written += sizeof(val);
  }

  VG_(OSetWord_ResetIter)(io_vec->system_calls);

  SE_(cmd_msg) *cmd_msg = SE_(create_cmd_msg)(msg_type, bytes_written, data);
  bytes_written = SE_(write_msg_to_fd)(fd, cmd_msg, False);
  VG_(free)(data);
  SE_(free_msg)(cmd_msg);

  return bytes_written;
}

SizeT SE_(io_vec_size)(SE_(io_vec) * io_vec) {
  tl_assert(io_vec);

  return sizeof(VexArch)      /* Architecture type */
         + sizeof(VexEndness) /* Endness */
         + sizeof(Word)       /* System call count */
         + VG_(OSetWord_Size)(io_vec->system_calls) *
               sizeof(UWord) /* System calls */
         + sizeof(io_vec->random_seed) +
         2 * sizeof(VexGuestArchState) /* register states */
         + 2 * sizeof(UInt) +          /* Address space counts */
         VG_(sizeRangeMap)(io_vec->initial_state.address_state) * 3 *
             sizeof(UWord) +
         VG_(sizeRangeMap)(io_vec->expected_state.address_state) * 3 *
             sizeof(UWord);
}
