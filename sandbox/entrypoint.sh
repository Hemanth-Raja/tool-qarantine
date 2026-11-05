#!/bin/sh
# Runs the tool under strace. The trace goes to /audit (a tmpfs the host reads
# before destroying the container). stdin/stdout stay attached for MCP stdio.
set -e
exec strace -f -qq -tt -s 200 -yy \
  -e trace=openat,open,creat,unlink,unlinkat,rename,renameat,mkdir,connect,sendto,execve,clone,clone3,fork,vfork \
  -o /audit/trace.log "$@"
