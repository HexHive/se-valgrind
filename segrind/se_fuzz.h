//
// Created by derrick on 4/3/20.
//

#ifndef SE_VALGRIND_SE_FUZZ_H
#define SE_VALGRIND_SE_FUZZ_H

#include "se_command_server.h"
#include "segrind_tool.h"

/**
 * @brief Fuzzes the region between [start, end] using the seed
 * @param seed
 * @param start
 * @param end
 */
void SE_(fuzz_region)(UInt *seed, Addr start, Addr end);

#endif // SE_VALGRIND_SE_FUZZ_H
