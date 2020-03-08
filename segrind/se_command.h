//
// Created by derrick on 3/8/20.
//
/**
 * @brief Defines available commands and message types
 */

#ifndef SE_VALGRIND_SE_COMMAND_H
#define SE_VALGRIND_SE_COMMAND_H

#include "se.h"

typedef enum se_message_type_t_ {
  SEMSG_FAIL = -1,  /* Request failed */
  SEMSG_OK,         /* Request succeeded */
  SEMSG_ACK,        /* Request receieved */
  SEMSG_SET_TGT,    /* Change target function */
  SEMSG_EXIT,       /* Shutdown */
  SEMSG_FUZZ,       /* Fuzz program state */
  SEMSG_EXECUTE,    /* Execute target function */
  SEMSG_SET_CTX,    /* Set program state for executing target function */
  SEMSG_READY,      /* Ready to accept and executed requests */
  SEMSG_RESET,      /* Bring to initial state */
  SEMSG_SET_SO_TGT, /* Set target function in shared library */
} SE_(cmd_msg_t);

typedef struct {
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
 * @return A message or -1 on failure
 */
SE_(cmd_msg) * SE_(make_cmd_msg)(SE_(cmd_msg_t) type, SizeT length, void *data);
void SE_(free_msg)(SE_(cmd_msg) * msg);

typedef enum cmd_result_t_ {
  SECMD_ERROR,        /* Request failed to fully execute */
  SECMD_OK,           /* Request successfully finished */
  SECMD_NOT_FOUND,    /* Function is not found */
  SECMD_INTERRUPTED,  /* Operation was interrupted by a signal */
  SECMD_TOO_MANY_INS, /* VM executed too many instructions */
  SECMD_FAILED_CTX,   /* Function did not accept IOVec */
} SE_(cmd_result_t);

#endif // SE_VALGRIND_SE_COMMAND_H
