//
// Created by derrick on 3/8/20.
//

#include "se.h"

#include "se_command.h"

#include "pub_tool_mallocfree.h"

const HChar *SE_MSG_MALLOC_TYPE = "SE_(cmd_msg)";

SE_(cmd_msg) *
    SE_(create_cmd_msg)(SE_(cmd_msg_t) type, SizeT length, const void *data) {
  void *new_data = NULL;
  if (length > 0) {
    new_data = VG_(malloc)(SE_MSG_MALLOC_TYPE, length);
    if (!new_data) {
      return (SE_(cmd_msg) *)0;
    }
    VG_(memcpy)(new_data, data, length);
  }

  SE_(cmd_msg) *res = VG_(malloc)(SE_MSG_MALLOC_TYPE, sizeof(SE_(cmd_msg)));
  if (!res) {
    if (new_data) {
      VG_(free)(new_data);
    }
    return (SE_(cmd_msg) *)0;
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

SizeT SE_(write_msg_to_fd)(Int fd, SE_(cmd_msg) * msg, Bool free_msg) {
  tl_assert(fd >= 0);
  tl_assert(msg);
  tl_assert(msg->msg_type >= SEMSG_FAIL && msg->msg_type < SEMSG_INVALID);

  SizeT bytes_written = 0;
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

  if (free_msg) {
    SE_(free_msg)(msg);
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
  case SEMSG_NEW_ALLOC:
    return "SEMSG_NEW_ALLOC";
  case SEMSG_FAILED_CTX:
    return "SEMSG_FAILED_CTX";
  case SEMSG_TOO_MANY_INS:
    return "SEMSG_TOO_MANY_INS";
  case SEMSG_TOO_MANY_ATTEMPTS:
    return "SEMSG_TOO_MANY_ATTEMPTS";
  case SEMSG_COVERAGE:
    return "SEMSG_COVERAGE";
  case SEMSG_TIMEOUT:
    return "SEMSG_TIMEOUT";
  default:
    tl_assert(0);
  }
}

SE_(cmd_msg) * SE_(read_msg_from_fd)(Int fd) {
  tl_assert(fd >= 0);

  SE_(cmd_msg_t) msg_type;
  if (VG_(read)(fd, &msg_type, sizeof(msg_type)) <= 0) {
    return NULL;
  }

  SizeT len;
  if (VG_(read)(fd, &len, sizeof(len)) <= 0) {
    return NULL;
  }

  char *buf = NULL;
  if (len > 0) {
    buf = VG_(malloc)(SE_MSG_MALLOC_TYPE, len);
    tl_assert(buf);
    if (VG_(read)(fd, buf, len) <= 0) {
      VG_(free)(buf);
      return NULL;
    }
  }

  SE_(cmd_msg) *result = SE_(create_cmd_msg)(msg_type, len, buf);
  VG_(free)(buf);
  return result;
}