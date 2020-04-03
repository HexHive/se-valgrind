project(se-valgrind)
cmake_minimum_required(VERSION 3.7)

set(VALGRIND_TOOL_NAME segrind)
set(VALGRIND_TOOL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${VALGRIND_TOOL_NAME})
set(VALGRIND_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install)
set(VALGRIND_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/build)

include_directories(include/
        VEX/pub/
        )

set(VALGRIND_TOOL_SRCS
        ${VALGRIND_TOOL_DIR}/se_clo.c
        ${VALGRIND_TOOL_DIR}/se_main.c
        ${VALGRIND_TOOL_DIR}/se_command.c
        ${VALGRIND_TOOL_DIR}/se_command_server.c
        ${VALGRIND_TOOL_DIR}/se_io_vec.c
        ${VALGRIND_TOOL_DIR}/se_taint.c
        ${VALGRIND_TOOL_DIR}/se_utils.c
        ${VALGRIND_TOOL_DIR}/se_fuzz.c
        )

set(VALGRIND_TOOL_INCS
        ${VALGRIND_TOOL_DIR}/se.h
        ${VALGRIND_TOOL_DIR}/se_command.h
        ${VALGRIND_INCS}
        ${VALGRIND_TOOL_DIR}/se_command_server.h
        ${VALGRIND_TOOL_DIR}/se_io_vec.h
        ${VALGRIND_TOOL_DIR}/se_defs.h
        ${VALGRIND_TOOL_DIR}/se_taint.h
        ${VALGRIND_TOOL_DIR}/se_utils.h
        ${VALGRIND_TOOL_DIR}/se_fuzz.h
        )

add_custom_command(
        OUTPUT ${VALGRIND_INSTALL_DIR}
        COMMAND mkdir -p ${VALGRIND_INSTALL_DIR}
        USES_TERMINAL
)

add_custom_command(
        OUTPUT ${VALGRIND_BUILD_DIR}
        COMMAND mkdir -p ${VALGRIND_BUILD_DIR}
        USES_TERMINAL
)

add_custom_target(
        ConfigureValgrind
        DEPENDS ${VALGRIND_BUILD_DIR}
        BYPRODUCTS ${VALGRIND_BUILD_DIR}/Makefile
        COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && bash ${CMAKE_CURRENT_SOURCE_DIR}/autogen.sh
        COMMAND cd ${VALGRIND_BUILD_DIR} && ${CMAKE_CURRENT_SOURCE_DIR}/configure --prefix=${VALGRIND_INSTALL_DIR} --srcdir=${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(
        BuildValgrind
        DEPENDS ${VALGRIND_INSTALL_DIR} ${VALGRIND_BUILD_DIR} ${VALGRIND_TOOL_SRCS} ${VALGRIND_TOOL_INCS}
        COMMAND make install
        WORKING_DIRECTORY ${VALGRIND_BUILD_DIR}
        BYPRODUCTS ${VALGRIND_TOOL_NAME}/${VALGRIND_TOOL_NAME}-amd64-linux
        SOURCES ${VALGRIND_TOOL_SRCS} ${VALGRIND_TOOL_INCS}
)

add_executable(
        DummyTarget
        ${VALGRIND_TOOL_SRCS} ${VALGRIND_TOOL_INCS}
)

add_dependencies(BuildValgrind ConfigureValgrind)