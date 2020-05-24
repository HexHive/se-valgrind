SEGrind
--------------

This is an implementation of Software Ethology, a function analysis technique
 that classifies functions by their effects on program state.
 The idea is to create Input/Output Vectors, or IOVecs, that contain an input
  program state, and then an expected output program state.
 Functions can accept an IOVec by executing to completion, and the resulting
  program state is the expected program state.
 Conversely, a function can reject an IOVec by either faulting during
  execution, or the program state does not match the expected program state.
  
 `SEGrind` creates a command server that reads commands from a FIFO pipe.
 When told to execute, the command server forks an an executor child to
  initialize the input state, and perform the actual code execution.
The executor communicates with the command server with a second FIFO pipe.

`SEGrind` is capable of generating IOVecs automatically through the use of
a coverage-guided fuzzer.
While generating IOVecs, if a segfault occurs, a backwards taint analysis is
 performed that determines what part of the input state should be a pointer.
The end result is that the IOVec includes a course-grained memory object
 layout of all accessed objects.
 
 `SEGrind` can execute any function in executables or shared libraries.
 In order to execute functions in a shared library, the user should compile
  `segrind_so_loader.c` into an executable, and provide that to `valgrind` as
   the application to load.
 On startup, `SEGrind` performs some analysis on the initial program state
 , and then issues a `SEMSG_READY` message to the command pipe as a command
  line input.
 After the `SEMSG_READY` message has been issued, a commander application can
  issue commands defined in `se_command.h`.
However, the command server enforces a finite state machine, and can refuse
 to perform a command if the command is not valid for the current state.
See `se_command_server.c` for valid commands for a given state.