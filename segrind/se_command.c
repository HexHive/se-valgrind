//
// Created by derrick on 3/8/20.
//

#include "se_command.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_mallocfree.h"

SE_(cmd_msg) *
    SE_(create_cmd_msg)(SE_(cmd_msg_t) type, SizeT length, void *data) {
  void *new_data = NULL;
  if (length > 0) {
    new_data = VG_(malloc)("SE_(cmd_msg)", length);
    if (!new_data) {
      return (SE_(cmd_msg) *)-1;
    }
    VG_(memcpy)(new_data, data, length);
  }

  SE_(cmd_msg) *res = VG_(malloc)("SE_(cmd_msg)", sizeof(SE_(cmd_msg)));
  if (!res) {
    if (new_data) {
      VG_(free)(new_data);
    }
    return (SE_(cmd_msg) *)-1;
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

SizeT SE_(write_msg_to_fd)(Int fd, const SE_(cmd_msg) * msg) {
  tl_assert(fd >= 0);
  tl_assert(msg);

  SizeT bytes_written;
  if (VG_(write)(fd, &msg->msg_type, sizeof(msg->msg_type)) <= 0) {
    return 0;
  }
  bytes_written += sizeof(msg->msg_type);

  if (VG_(write)(fd, &msg->length, sizeof(msg->length)) <= 0) {
    return 0;
  }
  bytes_written += sizeof(msg->length);

  if (msg->length > 0) {
    if (VG_(write)(fd, msg->data, msg->length) != msg->length) {
      return 0;
    }
    bytes_written += msg->length;
  }

  return bytes_written;
}

const HChar *SE_(msg_type_str)(SE_(cmd_msg_t) type) {
  switch (type) {
  case SEMSG_FAIL:
    return "SEMSG_FAIL";
  case SEMSG_OK:
    return "SEMSG_OK";
  case SEMSG_ACK:
    return "SEMSG_ACK";
  case SEMSG_SET_TGT:
    return "SEMSG_SET_TGT";
  case SEMSG_EXIT:
    return "SEMSG_EXIT";
  case SEMSG_FUZZ:
    return "SEMSG_FUZZ";
  case SEMSG_EXECUTE:
    return "SEMSG_EXECUTE";
  case SEMSG_SET_CTX:
    return "SEMSG_SET_CTX";
  case SEMSG_READY:
    return "SEMSG_READY";
  case SEMSG_RESET:
    return "SEMSG_RESET";
  case SEMSG_SET_SO_TGT:
    return "SEMSG_SET_SO_TGT";
  default:
    tl_assert(0);
  }
}