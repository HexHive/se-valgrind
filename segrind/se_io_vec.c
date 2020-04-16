//
// Created by derrick on 3/10/20.
//

#include "se_io_vec.h"
#include "se_command.h"
#include "se_defs.h"
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
  io_vec->initial_state.pointer_locations =
      VG_(newRangeMap)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free), 0);
  io_vec->initial_state.register_state =
      VG_(newXA)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free),
                 sizeof(SE_(register_value)));

  io_vec->expected_state =
      VG_(newRangeMap)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free), 0);

  io_vec->return_value.value.type = se_memo_return_value;
  io_vec->return_value.value.len = sizeof(RegWord);
  io_vec->return_value.value.buf =
      VG_(malloc)(SE_IOVEC_MALLOC_TYPE, io_vec->return_value.value.len);
  io_vec->return_value.is_ptr = False;

  return io_vec;
}

void SE_(free_io_vec)(SE_(io_vec) * io_vec) {
  tl_assert(io_vec);

  if (io_vec->initial_state.register_state)
    VG_(deleteXA)(io_vec->initial_state.register_state);

  if (io_vec->initial_state.address_state)
    VG_(deleteRangeMap)(io_vec->initial_state.address_state);

  if (io_vec->initial_state.pointer_locations)
    VG_(deleteRangeMap)(io_vec->initial_state.pointer_locations);

  if (io_vec->expected_state)
    VG_(deleteRangeMap)(io_vec->expected_state);

  if (io_vec->return_value.value.buf)
    VG_(free)(io_vec->return_value.value.buf);

  if (io_vec->system_calls)
    VG_(OSetWord_Destroy)(io_vec->system_calls);

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
         /* register_state */
         + sizeof(SizeT) +
         sizeof(SE_(register_value)) *
             VG_(sizeXA)(io_vec->initial_state.register_state) +
         /* address_space */
         sizeof(UInt) + /* Size of address map */
         VG_(sizeRangeMap)(io_vec->initial_state.address_state) * 3 *
             sizeof(UWord) +
         /* Pointer locations */
         sizeof(UInt) +
         VG_(sizeRangeMap)(io_vec->initial_state.pointer_locations) * 3 *
             sizeof(UWord) +
         /* Expected State */
         sizeof(UInt) /* Size of address map */
         + VG_(sizeRangeMap)(io_vec->expected_state) * 3 * sizeof(UWord) +
         /* Return value */
         sizeof(SizeT) + io_vec->return_value.value.len + sizeof(Bool) +
         /* System calls */
         sizeof(Word) /* System call count */
         + VG_(OSetWord_Size)(io_vec->system_calls) * sizeof(UWord);
}

SE_(io_vec) * SE_(read_io_vec_from_buf)(SizeT len, UChar *src) {
  tl_assert(len > 0);
  tl_assert(src);

  SizeT register_state_size;
  UInt rangemap_size;
  SizeT bytes_read = 0;

  SE_(io_vec) *io_vec =
      (SE_(io_vec) *)VG_(malloc)(SE_IOVEC_MALLOC_TYPE, sizeof(SE_(io_vec)));
  VG_(memset)(io_vec, 0, sizeof(SE_(io_vec)));

  VG_(memcpy)(&io_vec->host_arch, src + bytes_read, sizeof(io_vec->host_arch));
  bytes_read += sizeof(io_vec->host_arch);

  VG_(memcpy)
  (&io_vec->host_endness, src + bytes_read, sizeof(io_vec->host_endness));
  bytes_read += sizeof(io_vec->host_endness);

  VG_(memcpy)
  (&io_vec->random_seed, src + bytes_read, sizeof(io_vec->random_seed));
  bytes_read += sizeof(io_vec->random_seed);

  io_vec->initial_state.register_state =
      VG_(newXA)(VG_(malloc), SE_IOVEC_MALLOC_TYPE, VG_(free),
                 sizeof(SE_(register_value)));
  VG_(memcpy)
  (&register_state_size, src + bytes_read, sizeof(register_state_size));
  bytes_read += sizeof(register_state_size);
  for (; register_state_size > 0; register_state_size--) {
    SE_(register_value) reg_val;
    VG_(memcpy)
    (&reg_val.guest_state_offset, src + bytes_read,
     sizeof(reg_val.guest_state_offset));
    bytes_read += sizeof(reg_val.guest_state_offset);
    VG_(memcpy)(&reg_val.value, src + bytes_read, sizeof(reg_val.value));
    bytes_read += sizeof(reg_val.value);
    VG_(memcpy)(&reg_val.is_ptr, src + bytes_read, sizeof(reg_val.is_ptr));
    bytes_read += sizeof(reg_val.is_ptr);
    VG_(addToXA)(io_vec->initial_state.register_state, &reg_val);
  }
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
  io_vec->initial_state.pointer_locations =
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
    (io_vec->initial_state.pointer_locations, key_min, key_max, val);
  }

  io_vec->expected_state =
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
    (io_vec->expected_state, key_min, key_max, val);
  }

  io_vec->return_value.value.type = se_memo_return_value;
  VG_(memcpy)
  (&io_vec->return_value.value.len, src + bytes_read,
   sizeof(io_vec->return_value.value.len));
  bytes_read += sizeof(io_vec->return_value.value.len);
  io_vec->return_value.value.buf =
      VG_(malloc)(SE_IOVEC_MALLOC_TYPE, io_vec->return_value.value.len);
  VG_(memcpy)
  (io_vec->return_value.value.buf, src + bytes_read,
   io_vec->return_value.value.len);
  bytes_read += io_vec->return_value.value.len;
  VG_(memcpy)
  (&io_vec->return_value.is_ptr, src + bytes_read,
   sizeof(io_vec->return_value.is_ptr));
  bytes_read += sizeof(io_vec->return_value.is_ptr);

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
  SizeT bytes_written = 0;
  SizeT register_state_size;
  UChar *data = (UChar *)VG_(malloc)(SE_IOVEC_MALLOC_TYPE, io_vec_size);

  /* host_arch */
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
  register_state_size = VG_(sizeXA)(io_vec->initial_state.register_state);
  VG_(memcpy)
  (data + bytes_written, &register_state_size, sizeof(register_state_size));
  bytes_written += sizeof(register_state_size);
  for (SizeT i = 0; i < register_state_size; i++) {
    SE_(register_value) *reg_val =
        VG_(indexXA)(io_vec->initial_state.register_state, i);
    VG_(memcpy)
    (data + bytes_written, &reg_val->guest_state_offset,
     sizeof(reg_val->guest_state_offset));
    bytes_written += sizeof(reg_val->guest_state_offset);
    VG_(memcpy)(data + bytes_written, &reg_val->value, sizeof(reg_val->value));
    bytes_written += sizeof(reg_val->value);
    VG_(memcpy)
    (data + bytes_written, &reg_val->is_ptr, sizeof(reg_val->is_ptr));
    bytes_written += sizeof(reg_val->is_ptr);
  }
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
  /* pointer_locations */
  space_size = VG_(sizeRangeMap)(io_vec->initial_state.pointer_locations);
  VG_(memcpy)(data + bytes_written, &space_size, sizeof(space_size));
  bytes_written += sizeof(space_size);
  for (UInt i = 0; i < space_size; i++) {
    UWord key_min, key_max, val;
    VG_(indexRangeMap)
    (&key_min, &key_max, &val, io_vec->initial_state.pointer_locations, i);
    VG_(memcpy)(data + bytes_written, &key_min, sizeof(key_min));
    bytes_written += sizeof(key_min);
    VG_(memcpy)(data + bytes_written, &key_max, sizeof(key_max));
    bytes_written += sizeof(key_max);
    VG_(memcpy)(data + bytes_written, &val, sizeof(val));
    bytes_written += sizeof(val);
  }

  /* expected_state */
  /* register_state */
  //  VG_(memcpy)
  //  (data + bytes_written, &io_vec->expected_state.register_state.len,
  //   sizeof(io_vec->expected_state.register_state.len));
  //  bytes_written += sizeof(io_vec->expected_state.register_state.len);
  //  VG_(memcpy)
  //  (data + bytes_written, io_vec->expected_state.register_state.buf,
  //   io_vec->expected_state.register_state.len);
  //  bytes_written += io_vec->expected_state.register_state.len;
  space_size = VG_(sizeRangeMap)(io_vec->expected_state);
  VG_(memcpy)(data + bytes_written, &space_size, sizeof(space_size));
  bytes_written += sizeof(space_size);
  for (UInt i = 0; i < space_size; i++) {
    UWord key_min, key_max, val;
    VG_(indexRangeMap)
    (&key_min, &key_max, &val, io_vec->expected_state, i);
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
  //  VG_(memcpy)
  //  (data + bytes_written, &io_vec->initial_register_state_map.len,
  //   sizeof(io_vec->initial_register_state_map.len));
  //  bytes_written += sizeof(io_vec->initial_register_state_map.len);
  //  VG_(memcpy)
  //  (data + bytes_written, io_vec->initial_register_state_map.buf,
  //   io_vec->initial_register_state_map.len);
  //  bytes_written += io_vec->initial_register_state_map.len;

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
  if (io_vec->return_value.value.buf) {
    VG_(printf)
    ("return_value: 0x%lx %s\n", *(RegWord *)io_vec->return_value.value.buf,
     io_vec->return_value.is_ptr ? "O" : "X");
  } else {
    VG_(printf)("Return value is NULL\n");
  }

  VG_(printf)("system_calls: ");
  UWord syscall;
  VG_(OSetWord_ResetIter)(io_vec->system_calls);
  while (VG_(OSetWord_Next)(io_vec->system_calls, &syscall)) {
    VG_(printf)("%lu ", syscall);
  }
  //  VG_(printf)("\nregister_pointers: ");
  //  for (SizeT i = 0; i < io_vec->initial_register_state_map.len;
  //       i += sizeof(RegWord)) {
  //    RegWord reg = *(RegWord *)(io_vec->initial_register_state_map.buf + i);
  //    if (reg == OBJ_ALLOCATED_MAGIC) {
  //      VG_(printf)("%lu ", i);
  //    }
  //  }

  VG_(printf)("\nInitial State:\n");
  SE_(ppProgramState)(&io_vec->initial_state);
  VG_(printf)("Expected State:\n");
  UInt size = VG_(sizeRangeMap)(io_vec->expected_state);
  for (UInt i = 0; i < size; i++) {
    UWord addr_min, addr_max, val;
    VG_(indexRangeMap)
    (&addr_min, &addr_max, &val, io_vec->expected_state, i);
    if (val > 0) {
      VG_(printf)
      ("\t[ %p -- %p ] = %lu\n", (void *)addr_min, (void *)addr_max, val);
    }
  }
  VG_(printf)
  ("==========================================================================="
   "====================\n");
}

void SE_(ppProgramState)(SE_(program_state) * program_state) {
  tl_assert(program_state);

  UWord idx = VG_(sizeRangeMap)(program_state->address_state);
  VG_(printf)("Allocated addresses:\n");
  for (UWord i = 0; i < idx; i++) {
    UWord key_min, key_max, val;
    VG_(indexRangeMap)
    (&key_min, &key_max, &val, program_state->address_state, i);
    VG_(printf)("\t0x%016lx -- 0x%016lx = %lu\n", key_min, key_max, val);
  }

  VG_(printf)("pointer_locations:\n");
  UInt size = VG_(sizeRangeMap)(program_state->pointer_locations);
  for (UInt i = 0; i < size; i++) {
    UWord addr_min, addr_max, val;
    VG_(indexRangeMap)
    (&addr_min, &addr_max, &val, program_state->pointer_locations, i);
    if (val > 0) {
      VG_(printf)("\t%p = %p\n", (void *)addr_min, (void *)val);
    }
  }

  VG_(printf)("register_state:\n");
  for (UInt i = 0; i < VG_(sizeXA)(program_state->register_state); i++) {
    SE_(register_value) *reg_val =
        VG_(indexXA)(program_state->register_state, i);
    VG_(printf)
    ("\t%d = 0x%lx %s\n", reg_val->guest_state_offset, reg_val->value,
     reg_val->is_ptr ? "O" : "X");
  }
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
         io_vec->expected_state, current_addr);
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