//
// Created by derrick on 3/27/20.
//

#include "se_utils.h"
#include "pub_tool_mallocfree.h"

SizeT SE_(Memoize_OSetWord)(OSet *oset, UChar **dest) {
  tl_assert(oset);

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

  *dest = buf;

  return len;
}