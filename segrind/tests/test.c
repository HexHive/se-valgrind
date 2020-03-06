//
// Created by derrick on 3/6/20.
//
#include <stdio.h>
#include <stdlib.h>

int __attribute__((noinline)) foo(int *a, int b, int c) {
  printf("foo called with a = %p b = %d and c = %d\n", a, b, c);
  *a = b / c;
  return 0;
}

int main(int argc, char **argv) {
  int *a = (int *)malloc(sizeof(int));
  if (a) {
    return foo(a, argc, argc - 1);
  }

  return -1;
}