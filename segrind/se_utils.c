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