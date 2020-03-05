project(se-valgrind)
cmake_minimum_required(VERSION 3.7)

set(VALGRIND_TOOL_NAME segrind)
set(VALGRIND_TOOL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${VALGRIND_TOOL_NAME})
set(VALGRIND_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install)

include_directories(include/
        VEX/pub/
        )

set(VALGRIND_TOOL_SRCS
        ${VALGRIND_TOOL_DIR}/clo.c
        ${VALGRIND_TOOL_DIR}/se_main.c
        )

set(VALGRIND_TOOL_INCS
        ${VALGRIND_TOOL_DIR}/se.h
        ${VALGRIND_INCS}
        )

add_custom_command(
        OUTPUT ${VALGRIND_INSTALL_DIR}
        COMMAND mkdir -p ${VALGRIND_INSTALL_DIR}
)

add_custom_target(
        ConfigureValgrind
        DEPENDS ${VALGRIND_INSTALL_DIR}
        BYPRODUCTS Makefile
        COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && bash ${CMAKE_CURRENT_SOURCE_DIR}/autogen.sh
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/configure --prefix=${VALGRIND_INSTALL_DIR} --srcdir=${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(
        BuildValgrind
        DEPENDS ${VALGRIND_INSTALL_DIR}
        COMMAND make install
        BYPRODUCTS ${VALGRIND_TOOL_NAME}/${VALGRIND_TOOL_NAME}-amd64-linux
        SOURCES ${VALGRIND_TOOL_SRCS} ${VALGRIND_TOOL_INCS}
)

add_executable(
        DummyTarget
        ${VALGRIND_TOOL_SRCS} ${VALGRIND_TOOL_INCS}
)

add_dependencies(BuildValgrind ConfigureValgrind)