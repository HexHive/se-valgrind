//
// Created by derrick on 3/8/20.
//
/**
 * @brief Defines available commands and message types
 */
#ifndef SE_VALGRIND_SE_COMMAND_H
#define SE_VALGRIND_SE_COMMAND_H

#include "se.h"

const HChar *SE_MSG_MALLOC_TYPE;

/**
 * @brief The types of messages that can be sent between executor, command
 * server, and commander
 */
typedef enum se_message_type_t_ {
  SEMSG_FAIL = -1,        /* Request failed */
  SEMSG_OK,               /* Request succeeded */
  SEMSG_ACK,              /* Request receieved */
  SEMSG_SET_TGT,          /* Change target function */
  SEMSG_EXIT,             /* Shutdown */
  SEMSG_FUZZ,             /* Fuzz program state */
  SEMSG_EXECUTE,          /* Execute target function */
  SEMSG_SET_CTX,          /* Set program state for executing target function */
  SEMSG_READY,            /* Ready to accept and execute requests */
  SEMSG_RESET,            /* Bring to initial state */
  SEMSG_SET_SO_TGT,       /* Set target function in shared library */
  SEMSG_NEW_ALLOC,        /* A new allocated area is returned when fuzzing */
  SEMSG_FAILED_CTX,       /* The provided IOVec failed */
  SEMSG_TOO_MANY_INS,     /* The function executed too many instructions */
  SEMSG_TOO_MANY_ATTEMPTS /* Could not execute target function */
} SE_(cmd_msg_t);

/**
 * @brief The whole message
 */
typedef struct se_cmd_msg {
  SE_(cmd_msg_t) msg_type;
  SizeT length;
  void *data;
} SE_(cmd_msg);

/**
 * @brief Creates a new message.
 * @param type
 * @param length - The length of data
 * @param data - Data to be sent. Memory is duplicated in a separate buffer, so
 * no need to keep data around once this call successfully returns
 * @return A message or NULL on failure
 */
SE_(cmd_msg) *
    SE_(create_cmd_msg)(SE_(cmd_msg_t) type, SizeT length, const void *data);

/**
 * @brief Frees the message if not NULL
 * @param msg
 */
void SE_(free_msg)(SE_(cmd_msg) * msg);

/**
 * @brief Writes the message to the specified file descriptor
 * @param fd
 * @param msg
 * @return Number of bytes written or 0 on error
 */
SizeT SE_(write_msg_to_fd)(Int fd, SE_(cmd_msg) * msg, Bool free_msg);

/**
 * @brief Reads a single message from the specified file descriptor, which must
 * be freed later
 * @param fd
 * @return SE_(cmd_msg) or NULL on error
 */
SE_(cmd_msg) * SE_(read_msg_from_fd)(Int fd);

/**
 * @brief Returns a string for the message type
 * @param type
 * @return
 */
const HChar *SE_(msg_type_str)(SE_(cmd_msg_t) type);

#endif // SE_VALGRIND_SE_COMMAND_H
