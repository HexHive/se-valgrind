//
// Created by derrick on 5/13/20.
//
#include "segrind.h"
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Invalid arguments\n");
  }

  void *handle = dlopen(argv[1], RTLD_NOW);
  if (!handle) {
    fprintf(stderr, "dlopen(%s) failed\n", argv[1]);
  }

  VALGRIND_DO_CLIENT_REQUEST_STMT(SE_USERREQ_START_SERVER, 0, 0, 0, 0, 0);

  dlclose(handle);
  return 0;
}