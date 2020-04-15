//
// Created by derrick on 3/10/20.
//

#include "se_io_vec.h"
#include "se_command.h"
#include "se_utils.h"

#include "pub_tool_aspacemgr.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"

const HChar *SE_IOVEC_MALLOC_TYPE = "SE_(io_vec)";

SE_(io_vec) * SE_(create_io_vec)(void) {
  SE_(io_vec) *io_vec =
      (SE_(io_vec) *)VG_(malloc)(SE_IOVEC_MALLOC_TYPE, sizeof(SE_(io_vec)));
  VG_(memset)(io_vec, 0, sizeof(SE_(io_vec)));

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

  io_vec->initial_state.register_state.len = sizeof(VexGuestArchState);
  io_vec->initial_state.register_state.type = se_memo_arch_state;
  io_vec->initial_state.register_state.buf =
      VG_(malloc)(SE_IOVEC_MALLOC_TYPE, sizeof(VexGuestArchState));

  io_vec->expected_state.register_state.len = sizeof(VexGuestArchState);
  io_vec->expected_state.register_state.type = se_memo_arch_state;
  io_vec->expected_state.register_state.buf =
      VG_(malloc)(SE_IOVEC_MALLOC_TYPE, sizeof(VexGuestArchState));

  io_vec->initial_register_state_map.len = sizeof(VexGuestArchState);
  io_vec->initial_register_state_map.type = se_memo_arch_state;
  io_vec->initial_register_state_map.buf =
      VG_(malloc)(SE_IOVEC_MALLOC_TYPE, sizeof(VexGuestArchState));

  io_vec->return_value.value.type = se_memo_return_value;
  io_vec->return_value.value.len = sizeof(RegWord);
  io_vec->return_value.value.buf =
      VG_(malloc)(SE_IOVEC_MALLOC_TYPE, io_vec->return_value.value.len);
  io_vec->return_value.is_ptr = False;

  return io_vec;
}

void SE_(free_io_vec)(SE_(io_vec) * io_vec) {
  tl_assert(io_vec);
  if (io_vec->system_calls)
    VG_(OSetWord_Destroy)(io_vec->system_calls);

  if (io_vec->initial_state.address_state)
    VG_(deleteRangeMap)(io_vec->initial_state.address_state);

  if (io_vec->expected_state.address_state)
    VG_(deleteRangeMap)(io_vec->expected_state.address_state);

  if (io_vec->initial_state.register_state.buf)
    VG_(free)(io_vec->initial_state.register_state.buf);

  if (io_vec->expected_state.register_state.buf)
    VG_(free)(io_vec->expected_state.register_state.buf);

  if (io_vec->initial_register_state_map.buf)
    VG_(free)(io_vec->initial_register_state_map.buf);

  if (io_vec->return_value.value.buf)
    VG_(free)(io_vec->return_value.value.buf);

  VG_(free)(io_vec);
}

SizeT SE_(write_io_vec_to_fd)(Int fd, SE_(cmd_msg_t) msg_type,
                              SE_(io_vec) * io_vec) {
  tl_assert(fd > 0);
  tl_assert(io_vec);

  SE_(memoized_object) obj;
  SE_(write_io_vec_to_buf)(io_vec, &obj);

  SE_(cmd_msg) *cmd_msg = SE_(create_cmd_msg)(msg_type, obj.len, obj.buf);
  SizeT bytes_written = SE_(write_msg_to_fd)(fd, cmd_msg, False);
  VG_(free)(obj.buf);
  SE_(free_msg)(cmd_msg);

  return bytes_written;
}

SizeT SE_(io_vec_size)(SE_(io_vec) * io_vec) {
  tl_assert(io_vec);

  return sizeof(VexArch)               /* Architecture type */
         + sizeof(VexEndness)          /* Endness */
         + sizeof(io_vec->random_seed) /* Random seed */
         /* Initial state */
         + sizeof(SizeT) + io_vec->initial_state.register_state.len +
         sizeof(UInt) + /* Size of address map */
         VG_(sizeRangeMap)(io_vec->initial_state.address_state) * 3 *
             sizeof(UWord)
         /* Expected State */
         + sizeof(SizeT) + io_vec->expected_state.register_state.len +
         sizeof(UInt) /* Size of address map */
         + VG_(sizeRangeMap)(io_vec->expected_state.address_state) * 3 *
               sizeof(UWord) +
         /* Return value */
         sizeof(SizeT) + io_vec->return_value.value.len + sizeof(Bool) +
         /* Register state map */
         sizeof(SizeT) + io_vec->initial_register_state_map.len +
         /* System calls */
         sizeof(Word) /* System call count */
         + VG_(OSetWord_Size)(io_vec->system_calls) * sizeof(UWord);
}

SE_(io_vec) * SE_(read_io_vec_from_buf)(SizeT len, UChar *src) {
  tl_assert(len > 0);
  tl_assert(src);

  SE_(io_vec) *io_vec =
      (SE_(io_vec) *)VG_(malloc)(SE_IOVEC_MALLOC_TYPE, sizeof(SE_(io_vec)));
  VG_(memset)(io_vec, 0, sizeof(SE_(io_vec)));

  SizeT bytes_read = 0;
  VG_(memcpy)(&io_vec->host_arch, src + bytes_read, sizeof(io_vec->host_arch));
  bytes_read += sizeof(io_vec->host_arch);

  VG_(memcpy)
  (&io_vec->host_endness, src + bytes_read, sizeof(io_vec->host_endness));
  bytes_read += sizeof(io_vec->host_endness);

  VG_(memcpy)
  (&io_vec->random_seed, src + bytes_read, sizeof(io_vec->random_seed));
  bytes_read += sizeof(io_vec->random_seed);

  io_vec->initial_state.register_state.type = se_memo_arch_state;
  VG_(memcpy)
  (&io_vec->initial_state.register_state.len, src + bytes_read,
   sizeof(io_vec->initial_state.register_state.len));
  bytes_read += sizeof(io_vec->initial_state.register_state.len);

  io_vec->initial_state.register_state.buf = VG_(malloc)(
      SE_IOVEC_MALLOC_TYPE, io_vec->initial_state.register_state.len);
  VG_(memcpy)
  (io_vec->initial_state.register_state.buf, src + bytes_read,
   io_vec->initial_state.register_state.len);
  bytes_read += io_vec->initial_state.register_state.len;
  UInt rangemap_size;
  io_vec->initial_state.address_state =
      VG_(newRangeMap)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free), 0);
  VG_(memcpy)(&rangemap_size, src + bytes_read, sizeof(rangemap_size));
  bytes_read += sizeof(rangemap_size);
  for (; rangemap_size > 0; rangemap_size--) {
    UWord key_min, key_max, val;
    VG_(memcpy)(&key_min, src + bytes_read, sizeof(key_min));
    bytes_read += sizeof(key_min);
    VG_(memcpy)(&key_max, src + bytes_read, sizeof(key_max));
    bytes_read += sizeof(key_max);
    VG_(memcpy)(&val, src + bytes_read, sizeof(val));
    bytes_read += sizeof(val);
    VG_(bindRangeMap)
    (io_vec->initial_state.address_state, key_min, key_max, val);
  }

  io_vec->expected_state.register_state.type = se_memo_arch_state;
  VG_(memcpy)
  (&io_vec->expected_state.register_state.len, src + bytes_read,
   sizeof(io_vec->expected_state.register_state.len));
  bytes_read += sizeof(io_vec->expected_state.register_state.len);
  io_vec->expected_state.register_state.buf = VG_(malloc)(
      SE_IOVEC_MALLOC_TYPE, io_vec->expected_state.register_state.len);
  VG_(memcpy)
  (io_vec->expected_state.register_state.buf, src + bytes_read,
   io_vec->expected_state.register_state.len);
  bytes_read += io_vec->expected_state.register_state.len;
  io_vec->expected_state.address_state =
      VG_(newRangeMap)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free), 0);
  VG_(memcpy)(&rangemap_size, src + bytes_read, sizeof(rangemap_size));
  bytes_read += sizeof(rangemap_size);
  for (; rangemap_size > 0; rangemap_size--) {
    UWord key_min, key_max, val;
    VG_(memcpy)(&key_min, src + bytes_read, sizeof(key_min));
    bytes_read += sizeof(key_min);
    VG_(memcpy)(&key_max, src + bytes_read, sizeof(key_max));
    bytes_read += sizeof(key_max);
    VG_(memcpy)(&val, src + bytes_read, sizeof(val));
    bytes_read += sizeof(val);
    VG_(bindRangeMap)
    (io_vec->expected_state.address_state, key_min, key_max, val);
  }

  io_vec->return_value.value.type = se_memo_return_value;
  VG_(memcpy)
  (&io_vec->return_value.value.len, src + bytes_read,
   sizeof(io_vec->return_value.value.len));
  bytes_read += sizeof(io_vec->return_value.value.len);
  io_vec->return_value.value.buf =
      VG_(malloc)(SE_IOVEC_MALLOC_TYPE, io_vec->return_value.value.len);
  VG_(memcpy)
  (&io_vec->return_value.value.buf, src + bytes_read,
   io_vec->return_value.value.len);
  bytes_read += io_vec->return_value.value.len;
  VG_(memcpy)
  (&io_vec->return_value.is_ptr, src + bytes_read,
   sizeof(io_vec->return_value.is_ptr));
  bytes_read += sizeof(io_vec->return_value.is_ptr);

  io_vec->initial_register_state_map.type = se_memo_arch_state;
  VG_(memcpy)
  (&io_vec->initial_register_state_map.len, src + bytes_read,
   sizeof(io_vec->initial_register_state_map.len));
  bytes_read += sizeof(io_vec->initial_register_state_map.len);
  io_vec->initial_register_state_map.buf =
      VG_(malloc)(SE_IOVEC_MALLOC_TYPE, io_vec->initial_register_state_map.len);
  VG_(memcpy)
  (io_vec->initial_register_state_map.buf, src + bytes_read,
   io_vec->initial_register_state_map.len);
  bytes_read += io_vec->initial_register_state_map.len;

  io_vec->system_calls =
      VG_(OSetWord_Create)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free));
  VG_(memcpy)(&rangemap_size, src + bytes_read, sizeof(rangemap_size));
  bytes_read += sizeof(rangemap_size);
  for (; rangemap_size > 0; rangemap_size--) {
    UWord syscall_num;
    VG_(memcpy)(&syscall_num, src + bytes_read, sizeof(syscall_num));
    bytes_read += sizeof(syscall_num);
    VG_(OSetWord_Insert)(io_vec->system_calls, syscall_num);
  }

  return io_vec;
}

void SE_(write_io_vec_to_buf)(SE_(io_vec) * io_vec,
                              SE_(memoized_object) * dest) {
  tl_assert(dest);
  tl_assert(io_vec);

  SizeT io_vec_size = SE_(io_vec_size)(io_vec);
  UChar *data = (UChar *)VG_(malloc)(SE_IOVEC_MALLOC_TYPE, io_vec_size);

  /* host_arch */
  SizeT bytes_written = 0;
  VG_(memcpy)(data, &io_vec->host_arch, sizeof(io_vec->host_arch));
  bytes_written += sizeof(io_vec->host_arch);

  /* host_endness */
  VG_(memcpy)
  (data + bytes_written, &io_vec->host_endness, sizeof(io_vec->host_endness));
  bytes_written += sizeof(io_vec->host_endness);

  /* random_seed */
  VG_(memcpy)
  (data + bytes_written, &io_vec->random_seed, sizeof(io_vec->random_seed));
  bytes_written += sizeof(io_vec->random_seed);

  /* initial_state */
  /* register_state */
  VG_(memcpy)
  (data + bytes_written, &io_vec->initial_state.register_state.len,
   sizeof(io_vec->initial_state.register_state.len));
  bytes_written += sizeof(io_vec->initial_state.register_state.len);
  VG_(memcpy)
  (data + bytes_written, io_vec->initial_state.register_state.buf,
   io_vec->initial_state.register_state.len);
  bytes_written += io_vec->initial_state.register_state.len;
  /* address_space */
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

  /* expected_state */
  /* register_state */
  VG_(memcpy)
  (data + bytes_written, &io_vec->expected_state.register_state.len,
   sizeof(io_vec->expected_state.register_state.len));
  bytes_written += sizeof(io_vec->expected_state.register_state.len);
  VG_(memcpy)
  (data + bytes_written, io_vec->expected_state.register_state.buf,
   io_vec->expected_state.register_state.len);
  bytes_written += io_vec->expected_state.register_state.len;
  /* address_space */
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

  /* Return value */
  VG_(memcpy)
  (data + bytes_written, &io_vec->return_value.value.len,
   sizeof(io_vec->return_value.value.len));
  bytes_written += sizeof(io_vec->return_value.value.len);
  VG_(memcpy)
  (data + bytes_written, io_vec->return_value.value.buf,
   io_vec->return_value.value.len);
  bytes_written += io_vec->return_value.value.len;
  VG_(memcpy)
  (data + bytes_written, &io_vec->return_value.is_ptr,
   sizeof(io_vec->return_value.is_ptr));
  bytes_written += sizeof(io_vec->return_value.is_ptr);

  /* initial_register_state_map */
  VG_(memcpy)
  (data + bytes_written, &io_vec->initial_register_state_map.len,
   sizeof(io_vec->initial_register_state_map.len));
  bytes_written += sizeof(io_vec->initial_register_state_map.len);
  VG_(memcpy)
  (data + bytes_written, io_vec->initial_register_state_map.buf,
   io_vec->initial_register_state_map.len);
  bytes_written += io_vec->initial_register_state_map.len;

  /* system_calls */
  Word count = VG_(OSetWord_Size)(io_vec->system_calls);
  VG_(memcpy)(data + bytes_written, &count, sizeof(count));
  bytes_written += sizeof(count);
  UWord syscall_num;
  while (VG_(OSetWord_Next)(io_vec->system_calls, &syscall_num)) {
    VG_(memcpy)(data + bytes_written, &syscall_num, sizeof(syscall_num));
    bytes_written += sizeof(syscall_num);
  }

  VG_(OSetWord_ResetIter)(io_vec->system_calls);

  dest->len = bytes_written;
  dest->buf = data;
  dest->type = se_memo_io_vec;
}

void SE_(ppIOVec)(SE_(io_vec) * io_vec) {
  tl_assert(io_vec);

  VG_(printf)
  ("==========================================================================="
   "====================\n");
  VG_(printf)("host_arch:    %s\n", LibVEX_ppVexArch(io_vec->host_arch));
  VG_(printf)("host_endness: %s\n", LibVEX_ppVexEndness(io_vec->host_endness));
  VG_(printf)("random_seed:  %u\n", io_vec->random_seed);
  VG_(printf)
  ("return_value: 0x%lx %s\n", *(RegWord *)io_vec->return_value.value.buf,
   io_vec->return_value.is_ptr ? "O" : "X");

  VG_(printf)("System Calls: ");
  UWord syscall;
  VG_(OSetWord_ResetIter)(io_vec->system_calls);
  while (VG_(OSetWord_Next)(io_vec->system_calls, &syscall)) {
    VG_(printf)("%lu ", syscall);
  }
  VG_(printf)("\nRegister Pointers: ");
  for (SizeT i = 0; i < io_vec->initial_register_state_map.len;
       i += sizeof(RegWord)) {
    RegWord reg = *(RegWord *)(io_vec->initial_register_state_map.buf + i);
    if (reg == OBJ_ALLOCATED_MAGIC) {
      VG_(printf)("%lu ", i);
    }
  }

  VG_(printf)("\nInitial State:\n");
  SE_(ppProgramState)(&io_vec->initial_state);
  VG_(printf)("Expected State:\n");
  SE_(ppProgramState)(&io_vec->expected_state);
  VG_(printf)
  ("==========================================================================="
   "====================\n");
}

void SE_(ppProgramState)(SE_(program_state) * program_state) {
  tl_assert(program_state);

  UWord idx = VG_(sizeRangeMap)(program_state->address_state);
  Bool in_obj = False;
  VG_(printf)("Allocated addresses:\n");
  for (UWord i = 0; i < idx; i++) {
    UWord key_min, key_max, val;
    VG_(indexRangeMap)
    (&key_min, &key_max, &val, program_state->address_state, i);
    if (val & OBJ_START_MAGIC) {
      in_obj = True;
      VG_(printf)("\t%p [", (void *)key_min);
    }

    if (in_obj && (val & ALLOCATED_SUBPTR_MAGIC)) {
      VG_(printf)("PTR: [%016lx -- %016lx]\n", key_min, key_max);
    }

    if (val & OBJ_END_MAGIC) {
      in_obj = False;
      VG_(printf)("] %p\n", (void *)key_max);
    }
  }

  SE_(ppMemoizedObject)(&program_state->register_state);
}

Bool SE_(current_state_matches_expected)(SE_(io_vec) * io_vec,
                                         SE_(return_value) * return_value) {
  tl_assert(io_vec);
  tl_assert(return_value);

  SE_(return_value) *expected_return = &io_vec->return_value;

  // Check return values
  if (expected_return->is_ptr != return_value->is_ptr) {
    return False;
  }

  if (!expected_return->is_ptr) {
    Long expected_val = *(Long *)expected_return->value.buf;
    Long actual_val = *(Long *)return_value->value.buf;

    if (expected_val < 0 && actual_val > 0) {
      return False;
    }
    if (expected_val > 0 && actual_val < 0) {
      return False;
    }
    if (expected_val == 0 && actual_val != 0) {
      return False;
    }
    if (expected_val != 0 && actual_val == 0) {
      return False;
    }
  }

  /* Check address state */
  UInt size = VG_(sizeRangeMap)(io_vec->initial_state.address_state);
  Bool in_obj = False;
  for (UInt i = 0; i < size; i++) {
    UWord addr_min, addr_max, val;
    VG_(indexRangeMap)
    (&addr_min, &addr_max, &val, io_vec->initial_state.address_state, i);
    if (val & OBJ_START_MAGIC) {
      in_obj = True;
    }
    if (in_obj && !(val & ALLOCATED_SUBPTR_MAGIC)) {
      UWord expected_min_addr, expected_max_addr, expected_val;
      for (UWord current_addr = addr_min; current_addr <= addr_max;
           current_addr++) {
        VG_(lookupRangeMap)
        (&expected_min_addr, &expected_max_addr, &expected_val,
         io_vec->expected_state.address_state, current_addr);
        if (VG_(memcmp)((void *)current_addr, &expected_val, 1) != 0) {
          return False;
        }
      }
    } else if (in_obj && (val & ALLOCATED_SUBPTR_MAGIC)) {
      /* All allocated pointers should be valid, so if this current value
       * is not valid, then it has been overwritten with data */
      Addr current_addr = *(Addr *)addr_min;
      Bool is_valid =
          VG_(am_is_valid_for_client)(current_addr, 1, VKI_PROT_READ) ||
          VG_(am_is_valid_for_client)(current_addr, 1, VKI_PROT_WRITE) ||
          VG_(am_is_valid_for_client)(current_addr, 1, VKI_PROT_EXEC);
      if (!is_valid) {
        return False;
      }
    }
    if (val & OBJ_END_MAGIC) {
      in_obj = False;
    }
  }

  return True;
}