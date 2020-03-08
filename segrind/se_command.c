//
// Created by derrick on 3/8/20.
//

#include "se_command.h"
#include "pub_tool_mallocfree.h"

SE_(cmd_msg) *
    SE_(make_cmd_msg)(SE_(cmd_msg_t) type, SizeT length, void *data) {
  void *new_data = NULL;
  if (length > 0) {
    new_data = VG_(malloc)("SE_(cmd_msg)", length);
    if (!new_data) {
      return -1;
    }
    VG_(memcpy)(new_data, data, length);
  }

  SE_(cmd_msg) *res = VG_(malloc)("SE_(cmd_msg)", sizeof(SE_(cmd_msg)));
  if (!res) {
    if (new_data) {
      VG_(free)(new_data);
    }
    return -1;
  }

  res->data = new_data;
  res->length = length;
  res->msg_type = type;

  return res;
}

void SE_(free_msg)(SE_(cmd_msg) * msg) {
  if (msg) {
    if (msg->data) {
      VG_(free)(msg->data);
    }
    VG_(free)(msg);
  }
}