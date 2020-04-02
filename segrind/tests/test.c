//
// Created by derrick on 3/6/20.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

char *global1 = NULL;

int __attribute__((noinline)) foo(int *a, int b, int c) {
  //  printf("foo called with a = %p b = %d and c = %d\n", a, b, c);
  *a = b / c;
  return 0;
}

int __attribute__((noinline)) is_pid_and_argc_even(int argc) {
  pid_t pid = getpid();
  printf("argc = %d, pid = %d\n", argc, pid);
  if (argc % 2 == 0 && pid % 2 == 0) {
    return 1;
  }

  return 0;
}

void __attribute__((noinline)) print_global1(void) {
  //  printf("&global1 = %p\n", &global1);
  global1[0] = 'a';
}

int main(int argc, char **argv) {
  global1 = strdup(argv[0]);

  //  int *a = (int *)malloc(sizeof(int));
  //  if (a) {
  //    return foo(a, argc, argc - 1);
  //  }

  return is_pid_and_argc_even(argc);
}