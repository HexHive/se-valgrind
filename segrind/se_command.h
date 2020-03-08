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
  ZMSG_FAIL = -1,  /* Request failed */
  ZMSG_OK,         /* Request succeeded */
  ZMSG_ACK,        /* Request receieved */
  ZMSG_SET_TGT,    /* Change target function */
  ZMSG_EXIT,       /* Shutdown */
  ZMSG_FUZZ,       /* Fuzz program state */
  ZMSG_EXECUTE,    /* Execute target function */
  ZMSG_SET_CTX,    /* Set program state for executing target function */
  ZMSG_READY,      /* Ready to accept and executed requests */
  ZMSG_RESET,      /* Bring to initial state */
  ZMSG_SET_SO_TGT, /* Set target function in shared library */
} SE_(cmd_msg_t);

typedef struct {
  SE_(cmd_msg_t) msg_type;
  SizeT length;
  void *data;
} SE_(cmd_msg);

/**
 * @brief Creates a new message, freed when written to a pipe.
 * @param type
 * @param length - The length of data
 * @param data - Data to be sent. Memory is duplicated in a separate buffer, so
 * no need to keep data around once this call successfully returns
 * @return A message or -1 on failure
 */
SE_(cmd_msg) * SE_(make_cmd_msg)(SE_(cmd_msg_t) type, SizeT length, void *data);
void SE_(free_msg)(SE_(cmd_msg) * msg);

typedef enum cmd_result_t_ {
  ZCMD_ERROR,        /* Request failed to fully execute */
  ZCMD_OK,           /* Request successfully finished */
  ZCMD_NOT_FOUND,    /* Function is not found */
  ZCMD_INTERRUPTED,  /* Operation was interrupted by a signal */
  ZCMD_TOO_MANY_INS, /* VM executed too many instructions */
  ZCMD_FAILED_CTX,   /* Function did not accept IOVec */
} SE_(cmd_result_t);

#endif // SE_VALGRIND_SE_COMMAND_H
