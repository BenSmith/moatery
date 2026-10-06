"""The seccomp profiles a hut's workload runs under, as podman reads
them. They are moathut's own, taken from podman's default as
containers-common 0.67.2 ships it, its capability conditions resolved
against the hut's, refusing more: making a namespace, in which the hut's
user would be root, and the mount calls; the keyring, a vsock, and
io_uring. `strict`, the default, refuses as well the calls that reach
into another process, which `debug` allows. They change when this
module does, not when podman's default does.

libseccomp reads a rule naming one argument twice as matching anything,
lets the overlapping rule with fewer conditions win whatever the order,
and will not load a refusal and an allow of socket's family together.
So a call is in one entry, or in entries whose conditions cannot both
hold, no entry names an argument twice, and a family is allowed by
naming it: a vsock is refused by being in no entry.

What is refused on purpose fails with EPERM, but for clone3, which
fails with ENOSYS so glibc falls back to clone, whose flags can be
filtered, and the keyring and io_uring, which programs do without when
they are not implemented. A call or a family no entry names fails with
ENOSYS as well.
"""

import json

from .units import CAPABILITIES

EPERM = 1
EINVAL = 22
ENOSYS = 38

PROFILES = ("strict", "debug")
DEFAULT = "strict"

# podman's outright allows, less what this narrows; and futex2's, which
# podman refuses, and which do what futex does.
ALLOWED = (
    "_llseek", "_newselect", "accept", "accept4", "access", "adjtimex",
    "alarm", "bind", "brk", "capget", "capset", "chdir", "chmod", "chown",
    "chown32", "clock_adjtime", "clock_adjtime64", "clock_getres",
    "clock_getres_time64", "clock_gettime", "clock_gettime64",
    "clock_nanosleep", "clock_nanosleep_time64", "close", "close_range",
    "connect", "copy_file_range", "creat", "dup", "dup2", "dup3",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_ctl_old",
    "epoll_pwait", "epoll_pwait2", "epoll_wait", "epoll_wait_old",
    "eventfd", "eventfd2", "execve", "execveat", "exit", "exit_group",
    "faccessat", "faccessat2", "fadvise64", "fadvise64_64", "fallocate",
    "fanotify_init", "fanotify_mark", "fchdir", "fchmod", "fchmodat",
    "fchmodat2", "fchown", "fchown32", "fchownat", "fcntl", "fcntl64",
    "fdatasync", "fgetxattr", "flistxattr", "flock", "fork",
    "fremovexattr", "fsetxattr", "fstat", "fstat64", "fstatat64",
    "fstatfs", "fstatfs64", "fsync", "ftruncate", "ftruncate64", "futex",
    "futex_requeue", "futex_time64", "futex_wait", "futex_waitv",
    "futex_wake", "futimesat", "get_mempolicy", "get_robust_list",
    "get_thread_area", "getcpu", "getcwd", "getdents", "getdents64",
    "getegid", "getegid32", "geteuid", "geteuid32", "getgid", "getgid32",
    "getgroups", "getgroups32", "getitimer", "getpeername", "getpgid",
    "getpgrp", "getpid", "getppid", "getpriority", "getrandom",
    "getresgid", "getresgid32", "getresuid", "getresuid32", "getrlimit",
    "getrusage", "getsid", "getsockname", "getsockopt", "gettid",
    "gettimeofday", "getuid", "getuid32", "getxattr", "inotify_add_watch",
    "inotify_init", "inotify_init1", "inotify_rm_watch", "io_cancel",
    "io_destroy", "io_getevents", "io_setup", "io_submit", "ioctl",
    "ioprio_get", "ioprio_set", "ipc", "kill", "landlock_add_rule",
    "landlock_create_ruleset", "landlock_restrict_self", "lchown",
    "lchown32", "lgetxattr", "link", "linkat", "listen", "listxattr",
    "llistxattr", "lremovexattr", "lseek", "lsetxattr", "lstat", "lstat64",
    "madvise", "mbind", "membarrier", "memfd_create", "memfd_secret",
    "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2",
    "mlockall", "mmap", "mmap2", "mprotect", "mq_getsetattr", "mq_notify",
    "mq_open", "mq_timedreceive", "mq_timedreceive_time64", "mq_timedsend",
    "mq_timedsend_time64", "mq_unlink", "mremap", "msgctl", "msgget",
    "msgrcv", "msgsnd", "msync", "munlock", "munlockall", "munmap",
    "name_to_handle_at", "nanosleep", "newfstatat", "open", "openat",
    "openat2", "pause", "pidfd_open", "pidfd_send_signal", "pipe", "pipe2",
    "pkey_alloc", "pkey_free", "pkey_mprotect", "poll", "ppoll",
    "ppoll_time64", "prctl", "pread64", "preadv", "preadv2", "prlimit64",
    "process_mrelease", "pselect6", "pselect6_time64", "pwrite64",
    "pwritev", "pwritev2", "read", "readahead", "readlink", "readlinkat",
    "readv", "reboot", "recv", "recvfrom", "recvmmsg", "recvmmsg_time64",
    "recvmsg", "remap_file_pages", "removexattr", "rename", "renameat",
    "renameat2", "restart_syscall", "rmdir", "rseq", "rt_sigaction",
    "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo", "rt_sigreturn",
    "rt_sigsuspend", "rt_sigtimedwait", "rt_sigtimedwait_time64",
    "rt_tgsigqueueinfo", "sched_get_priority_max",
    "sched_get_priority_min", "sched_getaffinity", "sched_getattr",
    "sched_getparam", "sched_getscheduler", "sched_rr_get_interval",
    "sched_rr_get_interval_time64", "sched_setaffinity", "sched_setattr",
    "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp",
    "select", "semctl", "semget", "semop", "semtimedop",
    "semtimedop_time64", "send", "sendfile", "sendfile64", "sendmmsg",
    "sendmsg", "sendto", "set_mempolicy", "set_robust_list",
    "set_thread_area", "set_tid_address", "setfsgid", "setfsgid32",
    "setfsuid", "setfsuid32", "setgid", "setgid32", "setgroups",
    "setgroups32", "setitimer", "setpgid", "setpriority", "setregid",
    "setregid32", "setresgid", "setresgid32", "setresuid", "setresuid32",
    "setreuid", "setreuid32", "setrlimit", "setsid", "setsockopt",
    "setuid", "setuid32", "setxattr", "shmat", "shmctl", "shmdt", "shmget",
    "shutdown", "sigaltstack", "signal", "signalfd", "signalfd4",
    "sigprocmask", "sigreturn", "socketpair", "splice",
    "stat", "stat64", "statfs", "statfs64", "statx", "symlink",
    "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "syslog",
    "tee", "tgkill", "time", "timer_create", "timer_delete",
    "timer_getoverrun", "timer_gettime", "timer_gettime64",
    "timer_settime", "timer_settime64", "timerfd_create",
    "timerfd_gettime", "timerfd_gettime64", "timerfd_settime",
    "timerfd_settime64", "times", "tkill", "truncate", "truncate64",
    "ugetrlimit", "umask", "uname", "unlink", "unlinkat", "utime",
    "utimensat", "utimensat_time64", "utimes", "vfork", "wait4", "waitid",
    "waitpid", "write", "writev")

# Allowed on one architecture's kernel alone.
ARCH_ALLOWED = (
    (("ppc64le",), ("swapcontext", "sync_file_range2")),
    (("arm", "arm64"), ("arm_fadvise64_64", "arm_sync_file_range",
                        "breakpoint", "cacheflush", "set_tls",
                        "sync_file_range2")),
    (("amd64", "x32"), ("arch_prctl",)),
    (("amd64", "x32", "x86"), ("modify_ldt",)),
    (("s390", "s390x"), ("s390_pci_mmio_read", "s390_pci_mmio_write",
                         "s390_runtime_instr")),
    (("riscv64",), ("riscv_flush_icache",)),
)

# podman's, allowed with a capability. Those the hut holds are allowed,
# the rest refused.
GATED = (
    ("SYS_CHROOT", ("chroot",)),
    ("DAC_READ_SEARCH", ("open_by_handle_at",)),
    ("SYS_PACCT", ("acct",)),
    ("SYS_ADMIN", ("lookup_dcookie", "quotactl", "quotactl_fd",
                   "setdomainname", "sethostname", "setns")),
    ("SYS_ADMIN BPF", ("bpf",)),
    ("SYS_ADMIN PERFMON", ("perf_event_open",)),
    ("SYS_MODULE", ("delete_module", "finit_module", "init_module",
                    "query_module")),
    ("SYS_PTRACE", ("kcmp", "process_madvise")),
    ("SYS_RAWIO", ("ioperm", "iopl")),
    ("SYS_TIME", ("clock_settime", "clock_settime64", "settimeofday",
                  "stime")),
    ("SYS_TTY_CONFIG", ("vhangup",)),
)

# podman's own refusals, but futex2's.
OBSOLETE = (
    "bdflush", "cachestat", "io_pgetevents", "io_pgetevents_time64",
    "kexec_file_load", "kexec_load", "map_shadow_stack", "migrate_pages",
    "move_pages", "nfsservctl", "nice", "oldfstat", "oldlstat",
    "oldolduname", "oldstat", "olduname", "pciconfig_iobase",
    "pciconfig_read", "pciconfig_write", "sgetmask", "ssetmask", "swapoff",
    "swapon", "syscall", "sysfs", "uselib", "userfaultfd", "ustat", "vm86",
    "vm86old", "vmsplice")

# The mount calls: a hut's root holds no CAP_SYS_ADMIN, and nothing in it
# can be root in a namespace of its own.
MOUNTS = ("fsconfig", "fsmount", "fsopen", "fspick", "mount",
          "mount_setattr", "move_mount", "open_tree", "open_tree_attr",
          "pivot_root", "umount", "umount2")

# What reaches into another process: allowed by `debug`.
DEBUG = ("pidfd_getfd", "process_vm_readv", "process_vm_writev", "ptrace")

# io_uring's operations are not system calls the filter sees, and
# socketcall's are behind a pointer it cannot read.
NOT_IMPLEMENTED = ("add_key", "clone3", "io_uring_enter",
                   "io_uring_register", "io_uring_setup", "keyctl",
                   "request_key", "socketcall")

# CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC,
# CLONE_NEWUSER, CLONE_NEWPID and CLONE_NEWNET; unshare takes
# CLONE_NEWTIME too, which is part of clone's exit signal.
CLONE_NEW = (0x00020000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
             0x20000000, 0x40000000)
CLONE_NEWTIME = 0x00000080

# s390's clone takes the flags second.
S390 = ("s390", "s390x")

# socket's families, and netlink's protocols, below these. A vsock is
# refused: it reaches the host, or a VM's hypervisor, around the
# network namespace.
FAMILIES = 64
NETLINKS = 32
AF_NETLINK = 16
NETLINK_AUDIT = 9
AF_VSOCK = 40

MASK64 = 0xffffffffffffffff

# The personalities podman allows: Linux, Linux with UNAME26, with
# ADDR_NO_RANDOMIZE, with both, and a query.
PERSONALITIES = (0x0, 0x8, 0x20000, 0x20008, 0xffffffff)

ARCHES = (
    ("SCMP_ARCH_X86_64", ("SCMP_ARCH_X86", "SCMP_ARCH_X32")),
    ("SCMP_ARCH_AARCH64", ("SCMP_ARCH_ARM",)),
    ("SCMP_ARCH_MIPS64", ("SCMP_ARCH_MIPS", "SCMP_ARCH_MIPS64N32")),
    ("SCMP_ARCH_MIPS64N32", ("SCMP_ARCH_MIPS", "SCMP_ARCH_MIPS64")),
    ("SCMP_ARCH_MIPSEL64", ("SCMP_ARCH_MIPSEL", "SCMP_ARCH_MIPSEL64N32")),
    ("SCMP_ARCH_MIPSEL64N32", ("SCMP_ARCH_MIPSEL", "SCMP_ARCH_MIPSEL64")),
    ("SCMP_ARCH_S390X", ("SCMP_ARCH_S390",)),
)


def _cmp(index, op, value, value_two=0):
    return {"index": index, "value": value, "valueTwo": value_two,
            "op": f"SCMP_CMP_{op}"}


def _allow(names, args=(), **where):
    return {"names": sorted(names), "action": "SCMP_ACT_ALLOW",
            "args": list(args), **where}


def _refuse(names, errno=EPERM, args=(), **where):
    return {"names": sorted(names), "action": "SCMP_ACT_ERRNO",
            "errnoRet": errno, "args": list(args), **where}


def _no_namespace(name, flags, index, **where):
    """`name` allowed without a namespace flag in its argument `index`,
    refused with one."""
    mask = sum(flags)
    return [_allow([name], [_cmp(index, "MASKED_EQ", mask, 0)], **where),
            *(_refuse([name], EPERM, [_cmp(index, "MASKED_EQ", flag, flag)],
                      **where) for flag in flags)]


def _among(index, values):
    """Argument `index` one of `values`, as few comparisons as cover
    them, each an aligned block whose mask keeps the upper 32 bits: a
    32-bit argument is the register's lower half to the kernel, but all
    of it to the filter, which then refuses a value with upper bits set
    rather than taking it for another."""
    values, start, out = sorted(values), 0, []
    while start < len(values):
        first = values[start]
        size = 1
        while (first % (size * 2) == 0
               and values[start:start + size * 2]
               == list(range(first, first + size * 2))):
            size *= 2
        out.append(_cmp(index, "MASKED_EQ", MASK64 & ~(size - 1), first))
        start += size
    return out


def _gated(held):
    allowed, refused = [], []
    for caps, names in GATED:
        (allowed if set(caps.split()) & held else refused).extend(names)
    return allowed, refused


def profile(name, capabilities=CAPABILITIES):
    """The profile as podman reads it."""
    if name not in PROFILES:
        raise ValueError(f"no seccomp profile {name!r}")
    held = set(capabilities)
    gated, refused = _gated(held)
    allowed = [*ALLOWED, *gated]
    if name == "debug":
        allowed += DEBUG
    else:
        refused += DEBUG
    entries = [
        _allow(allowed),
        *(_allow(names, includes={"arches": list(arches)})
          for arches, names in ARCH_ALLOWED),
        *(_allow(["personality"], [_cmp(0, "EQ", p)])
          for p in PERSONALITIES),
        *_no_namespace("clone", CLONE_NEW, 0, excludes={"arches": [*S390]}),
        *_no_namespace("clone", CLONE_NEW, 1, includes={"arches": [*S390]}),
        *_no_namespace("unshare", (*CLONE_NEW, CLONE_NEWTIME), 0),
        *(_allow(["socket"], [arg]) for arg in _among(
            0, set(range(FAMILIES)) - {AF_NETLINK, AF_VSOCK})),
    ]
    if "AUDIT_WRITE" in held:
        entries.append(_allow(["socket"], [_cmp(0, "EQ", AF_NETLINK)]))
    else:
        # The audit socket's EINVAL is what tells sudo there is no audit.
        entries += [
            _refuse(["socket"], EINVAL, [_cmp(0, "EQ", AF_NETLINK),
                                         _cmp(2, "EQ", NETLINK_AUDIT)]),
            *(_allow(["socket"], [_cmp(0, "EQ", AF_NETLINK), arg])
              for arg in _among(2, set(range(NETLINKS)) - {NETLINK_AUDIT})),
        ]
    entries += [
        _refuse([*refused, *OBSOLETE, *MOUNTS]),
        _refuse(NOT_IMPLEMENTED, ENOSYS),
    ]
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": ENOSYS,
        "archMap": [{"architecture": arch, "subArchitectures": list(subs)}
                    for arch, subs in ARCHES],
        "syscalls": entries,
    }


def render(name):
    return json.dumps(profile(name), indent=1) + "\n"
