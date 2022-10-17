#include <iostream>

#include <seccomp.h>
#include <unistd.h>

#include "seccomp_interface.h"

// Shift + Alt + select with mouse
// openat causes python's open("filename", "w") to hang however it also causes numba to hang
static const int32_t seccomp_whitelist[] = {
     SCMP_SYS(access
  ), SCMP_SYS(arch_prctl
  ), SCMP_SYS(brk
  ), SCMP_SYS(clone
  ), SCMP_SYS(close
  ), SCMP_SYS(dup
  ), SCMP_SYS(execve
  ), SCMP_SYS(fcntl
  ), SCMP_SYS(fdatasync
  ), SCMP_SYS(fstat
  ), SCMP_SYS(futex
  ), SCMP_SYS(getcwd
  ), SCMP_SYS(getdents64
  ), SCMP_SYS(getegid
  ), SCMP_SYS(geteuid
  ), SCMP_SYS(getgid
  ), SCMP_SYS(getpid
  ), SCMP_SYS(getrandom
  ), SCMP_SYS(gettid
  ), SCMP_SYS(getuid
  ), SCMP_SYS(ioctl
  ), SCMP_SYS(link
  ), SCMP_SYS(lseek
  ), SCMP_SYS(lstat
  ), SCMP_SYS(mmap
  ), SCMP_SYS(mprotect
  ), SCMP_SYS(munmap
  ), SCMP_SYS(openat
  ), SCMP_SYS(pipe2
  ), SCMP_SYS(pread64
  ), SCMP_SYS(prlimit64
  ), SCMP_SYS(pwrite64
  ), SCMP_SYS(read
  ), SCMP_SYS(readlink
  ), SCMP_SYS(rt_sigaction
  ), SCMP_SYS(rt_sigprocmask
  ), SCMP_SYS(select
  ), SCMP_SYS(set_robust_list
  ), SCMP_SYS(set_tid_address
  ), SCMP_SYS(sigaltstack
  ), SCMP_SYS(stat
  ), SCMP_SYS(statfs
  ), SCMP_SYS(syscall
  ), SCMP_SYS(sysinfo
  ), SCMP_SYS(wait4
  ), SCMP_SYS(write
  ), SCMP_SYS(unlink
  )
};

void SeccompInterface::init() {
  std::cout << "Hello!" << std::endl;
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

  // To get system calls used
  // strace -qcf ./src/wise-app 2>&1 >/dev/null | awk '{print $NF}'
  for (int i = 0; i < 47; i++) {
      int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_whitelist[i], 0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

  seccomp_load(ctx);
}

SeccompInterface* SeccompInterface_new() {
  return new SeccompInterface();
}
void SeccompInterface_init(SeccompInterface* si) {
  si->init();
}