//
// Created by derrick on 5/13/20.
//

#ifndef SE_VALGRIND_SEGRIND_H
#define SE_VALGRIND_SEGRIND_H

#include "valgrind.h"

/*****************************************************
 * Shared Library Loader Requests
 *****************************************************/
typedef enum {
  SE_USERREQ_START_SERVER = VG_USERREQ_TOOL_BASE('S', 'E'),

} SE_ClientRequest;

#endif // SE_VALGRIND_SEGRIND_H
