//
// Created by derrick on 3/27/20.
//

#include "se_utils.h"
#include "pub_tool_mallocfree.h"

void SE_(Memoize_OSetWord)(OSet *oset, SE_(memoized_object) * dest) {
  tl_assert(oset);
  tl_assert(dest);

  SizeT bytes_written = 0;
  SizeT cov_size = VG_(OSetWord_Size)(oset);
  SizeT len = sizeof(Word) + cov_size * sizeof(Word);
  UChar *buf = VG_(malloc)(SE_TOOL_ALLOC_STR, len);

  VG_(memcpy)(buf, &cov_size, sizeof(cov_size));
  bytes_written += sizeof(cov_size);

  VG_(OSetWord_ResetIter)(oset);
  UWord addr;
  while (VG_(OSetWord_Next)(oset, &addr)) {
    VG_(memcpy)(buf + bytes_written, &addr, sizeof(addr));
    bytes_written += sizeof(addr);
  }

  dest->buf = buf;
  dest->len = len;
  dest->type = se_memo_oset_word;
}

void SE_(ppMemoizedObject)(SE_(memoized_object) * obj) {
  tl_assert(obj);

  SizeT idx;

  const HChar *start_fmt =
      "============================ %s ============================\n";

  switch (obj->type) {
  case se_memo_invalid:
    VG_(printf)(start_fmt, " INVALID ");
    goto finish;
  case se_memo_io_vec:
    VG_(printf)(start_fmt, "  IOVec  ");
    goto finish;
  case se_memo_oset_word:
    VG_(printf)(start_fmt, " OSetWord ");
    goto finish;
  case se_memo_arch_state:
    VG_(printf)(start_fmt, "Arch State");
    for (idx = 0; idx + sizeof(RegWord) < obj->len; idx += sizeof(RegWord)) {
      RegWord val = *(RegWord *)(obj->buf + idx);
      VG_(printf)("%p ", (void *)val);
      if (idx > 0 && idx % 128 == 0) {
        VG_(printf)("\n");
      }
    }
    for (/* keep same idx */; idx < obj->len; idx++) {
      if (idx > 0 && idx % 128 == 0) {
        VG_(printf)(" 0x");
      }
      VG_(printf)("%x", obj->buf[idx]);
    }
    break;
  default:
    tl_assert2(0, "Invalid memoized_obj type: %d", obj->type);
  }

finish:
  VG_(printf)("------------------------------------------------------------\n");
}