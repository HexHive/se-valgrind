//
// Created by derrick on 3/27/20.
//

#ifndef SE_VALGRIND_SE_UTILS_H
#define SE_VALGRIND_SE_UTILS_H

#include "se.h"

/**
 * @brief Copies an OSetWord size and data into allocated memory buffer
 * @param oset
 * @param dest - Where to write the location of the allocated memory buffer
 */
void SE_(Memoize_OSetWord)(OSet *oset, SE_(memoized_object) * dest);

/**
 * @brief Prints Memoized object using printf
 * @param obj
 */
void SE_(ppMemoizedObject)(SE_(memoized_object) * obj);

#endif // SE_VALGRIND_SE_UTILS_H
