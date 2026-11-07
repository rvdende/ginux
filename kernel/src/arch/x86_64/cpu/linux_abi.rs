#![forbid(unsafe_code)]
pub(super) const LINUX_READ_SYSCALL: u64 = 0;
pub(super) const LINUX_WRITE_SYSCALL: u64 = 1;
pub(super) const LINUX_OPEN_SYSCALL: u64 = 2;
pub(super) const LINUX_CLOSE_SYSCALL: u64 = 3;
pub(super) const LINUX_STAT_SYSCALL: u64 = 4;
pub(super) const LINUX_FSTAT_SYSCALL: u64 = 5;
pub(super) const LINUX_LSTAT_SYSCALL: u64 = 6;
pub(super) const LINUX_POLL_SYSCALL: u64 = 7;
pub(super) const LINUX_LSEEK_SYSCALL: u64 = 8;
pub(super) const LINUX_MMAP_SYSCALL: u64 = 9;
pub(super) const LINUX_MPROTECT_SYSCALL: u64 = 10;
pub(super) const LINUX_MUNMAP_SYSCALL: u64 = 11;
pub(super) const LINUX_BRK_SYSCALL: u64 = 12;
pub(super) const LINUX_RT_SIGACTION_SYSCALL: u64 = 13;
pub(super) const LINUX_RT_SIGPROCMASK_SYSCALL: u64 = 14;
pub(super) const LINUX_RT_SIGRETURN_SYSCALL: u64 = 15;
pub(super) const LINUX_RT_SIGPENDING_SYSCALL: u64 = 127;
pub(super) const LINUX_RT_SIGTIMEDWAIT_SYSCALL: u64 = 128;
pub(super) const LINUX_RT_SIGQUEUEINFO_SYSCALL: u64 = 129;
pub(super) const LINUX_RT_SIGSUSPEND_SYSCALL: u64 = 130;
pub(super) const LINUX_IOCTL_SYSCALL: u64 = 16;
pub(super) const LINUX_PREAD64_SYSCALL: u64 = 17;
pub(super) const LINUX_PWRITE64_SYSCALL: u64 = 18;
pub(super) const LINUX_READV_SYSCALL: u64 = 19;
pub(super) const LINUX_WRITEV_SYSCALL: u64 = 20;
pub(super) const LINUX_ACCESS_SYSCALL: u64 = 21;
pub(super) const LINUX_PIPE_SYSCALL: u64 = 22;
pub(super) const LINUX_SELECT_SYSCALL: u64 = 23;
pub(super) const LINUX_SCHED_YIELD_SYSCALL: u64 = 24;
pub(super) const LINUX_MREMAP_SYSCALL: u64 = 25;
pub(super) const LINUX_REMAP_FILE_PAGES_SYSCALL: u64 = 216;
pub(super) const LINUX_MSYNC_SYSCALL: u64 = 26;
pub(super) const LINUX_MINCORE_SYSCALL: u64 = 27;
pub(super) const LINUX_MADVISE_SYSCALL: u64 = 28;
pub(super) const LINUX_DUP_SYSCALL: u64 = 32;
pub(super) const LINUX_DUP2_SYSCALL: u64 = 33;
pub(super) const LINUX_PAUSE_SYSCALL: u64 = 34;
pub(super) const LINUX_NANOSLEEP_SYSCALL: u64 = 35;
pub(super) const LINUX_GETITIMER_SYSCALL: u64 = 36;
pub(super) const LINUX_ALARM_SYSCALL: u64 = 37;
pub(super) const LINUX_SETITIMER_SYSCALL: u64 = 38;
pub(super) const LINUX_GETPID_SYSCALL: u64 = 39;
pub(super) const LINUX_SENDFILE_SYSCALL: u64 = 40;
pub(super) const LINUX_SOCKET_SYSCALL: u64 = 41;
pub(super) const LINUX_ACCEPT_SYSCALL: u64 = 43;
pub(super) const LINUX_SOCKETPAIR_SYSCALL: u64 = 53;
pub(super) const LINUX_CONNECT_SYSCALL: u64 = 42;
pub(super) const LINUX_SENDTO_SYSCALL: u64 = 44;
pub(super) const LINUX_RECVFROM_SYSCALL: u64 = 45;
pub(super) const LINUX_SENDMSG_SYSCALL: u64 = 46;
pub(super) const LINUX_RECVMSG_SYSCALL: u64 = 47;
pub(super) const LINUX_SHUTDOWN_SYSCALL: u64 = 48;
pub(super) const LINUX_BIND_SYSCALL: u64 = 49;
pub(super) const LINUX_LISTEN_SYSCALL: u64 = 50;
pub(super) const LINUX_GETSOCKNAME_SYSCALL: u64 = 51;
pub(super) const LINUX_GETPEERNAME_SYSCALL: u64 = 52;
pub(super) const LINUX_SETSOCKOPT_SYSCALL: u64 = 54;
pub(super) const LINUX_GETSOCKOPT_SYSCALL: u64 = 55;
pub(super) const LINUX_CLONE_SYSCALL: u64 = 56;
pub(super) const LINUX_FORK_SYSCALL: u64 = 57;
pub(super) const LINUX_VFORK_SYSCALL: u64 = 58;
pub(super) const LINUX_EXECVE_SYSCALL: u64 = 59;
pub(super) const LINUX_WAIT4_SYSCALL: u64 = 61;
pub(super) const LINUX_KILL_SYSCALL: u64 = 62;
pub(super) const LINUX_TKILL_SYSCALL: u64 = 200;
pub(super) const LINUX_TIME_SYSCALL: u64 = 201;
pub(super) const LINUX_TGKILL_SYSCALL: u64 = 234;
pub(super) const LINUX_CLONE_VM: u64 = 0x0000_0100;
pub(super) const LINUX_CLONE_FS: u64 = 0x0000_0200;
pub(super) const LINUX_CLONE_FILES: u64 = 0x0000_0400;
pub(super) const LINUX_CLONE_SIGHAND: u64 = 0x0000_0800;
pub(super) const LINUX_CLONE_NEWNS: u64 = 0x0002_0000;
pub(super) const LINUX_CLONE_NEWUSER: u64 = 0x1000_0000;
pub(super) const LINUX_CLONE_THREAD: u64 = 0x0001_0000;
pub(super) const LINUX_CLONE_SYSVSEM: u64 = 0x0004_0000;
pub(super) const LINUX_CLONE_SETTLS: u64 = 0x0008_0000;
pub(super) const LINUX_CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub(super) const LINUX_CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub(super) const LINUX_CLONE_CHILD_SETTID: u64 = 0x0100_0000;
// Ignored by Linux since 2.6, but still passed by musl's pthread_create.
pub(super) const LINUX_CLONE_DETACHED: u64 = 0x0040_0000;
pub(super) const LINUX_CLONE_PIDFD: u64 = 0x0000_1000;
pub(super) const LINUX_CLONE_VFORK: u64 = 0x0000_4000;
pub(super) const LINUX_CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
pub(super) const LINUX_CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
pub(super) const LINUX_SIGCHLD: u64 = 17;
pub(super) const LINUX_SIGILL: u64 = 4;
pub(super) const LINUX_SIGTRAP: u64 = 5;
pub(super) const LINUX_SIGBUS: u64 = 7;
pub(super) const LINUX_SIGFPE: u64 = 8;
pub(super) const LINUX_SIGKILL: u64 = 9;
pub(super) const LINUX_BOUNDED_THREAD_CLONE_FLAGS: u64 = LINUX_CLONE_VM
    | LINUX_CLONE_FS
    | LINUX_CLONE_FILES
    | LINUX_CLONE_SIGHAND
    | LINUX_CLONE_THREAD
    | LINUX_CLONE_SYSVSEM
    | LINUX_CLONE_SETTLS
    | LINUX_CLONE_PARENT_SETTID
    | LINUX_CLONE_CHILD_CLEARTID
    | LINUX_CLONE_CHILD_SETTID;

/// Whether a thread clone with `flags` is one this kernel makes: a thread
/// shares its process's memory and signal handlers (CLONE_THREAD needs
/// CLONE_SIGHAND, which needs CLONE_VM), may set its thread pointer and tid
/// words, and ignores the exit signal in the low byte as Linux does. Its
/// descriptor table and filesystem context are its process's whether or not
/// CLONE_FILES and CLONE_FS are asked for: threads here have none of their
/// own.
pub(super) fn linux_thread_clone_flags_supported(flags: u64) -> bool {
    const REQUIRED: u64 = LINUX_CLONE_THREAD | LINUX_CLONE_SIGHAND | LINUX_CLONE_VM;
    const OPTIONAL: u64 = 0xff
        | LINUX_CLONE_FS
        | LINUX_CLONE_FILES
        | LINUX_CLONE_SYSVSEM
        | LINUX_CLONE_SETTLS
        | LINUX_CLONE_PARENT_SETTID
        | LINUX_CLONE_CHILD_CLEARTID
        | LINUX_CLONE_CHILD_SETTID
        | LINUX_CLONE_DETACHED
        // CLONE_PTRACE, CLONE_UNTRACED, CLONE_IO
        | 0x2000
        | 0x0080_0000
        | 0x8000_0000;
    flags & REQUIRED == REQUIRED && flags & !(REQUIRED | OPTIONAL) == 0
}
pub(super) const LINUX_EXIT_SYSCALL: u64 = 60;
pub(super) const LINUX_UNAME_SYSCALL: u64 = 63;
pub(super) const LINUX_FCNTL_SYSCALL: u64 = 72;
pub(super) const LINUX_FLOCK_SYSCALL: u64 = 73;
pub(super) const LINUX_FSYNC_SYSCALL: u64 = 74;
pub(super) const LINUX_FDATASYNC_SYSCALL: u64 = 75;
pub(super) const LINUX_TRUNCATE_SYSCALL: u64 = 76;
pub(super) const LINUX_FTRUNCATE_SYSCALL: u64 = 77;
pub(super) const LINUX_GETDENTS_SYSCALL: u64 = 78;
pub(super) const LINUX_GETCWD_SYSCALL: u64 = 79;
pub(super) const LINUX_CHDIR_SYSCALL: u64 = 80;
pub(super) const LINUX_FCHDIR_SYSCALL: u64 = 81;
pub(super) const LINUX_RENAME_SYSCALL: u64 = 82;
pub(super) const LINUX_MKDIR_SYSCALL: u64 = 83;
pub(super) const LINUX_RMDIR_SYSCALL: u64 = 84;
pub(super) const LINUX_CREAT_SYSCALL: u64 = 85;
pub(super) const LINUX_LINK_SYSCALL: u64 = 86;
pub(super) const LINUX_UNLINK_SYSCALL: u64 = 87;
pub(super) const LINUX_SYMLINK_SYSCALL: u64 = 88;
pub(super) const LINUX_READLINK_SYSCALL: u64 = 89;
pub(super) const LINUX_CHMOD_SYSCALL: u64 = 90;
pub(super) const LINUX_FCHMOD_SYSCALL: u64 = 91;
pub(super) const LINUX_CHOWN_SYSCALL: u64 = 92;
pub(super) const LINUX_FCHOWN_SYSCALL: u64 = 93;
pub(super) const LINUX_LCHOWN_SYSCALL: u64 = 94;
pub(super) const LINUX_UMASK_SYSCALL: u64 = 95;
pub(super) const LINUX_GETTIMEOFDAY_SYSCALL: u64 = 96;
pub(super) const LINUX_GETRLIMIT_SYSCALL: u64 = 97;
pub(super) const LINUX_GETRUSAGE_SYSCALL: u64 = 98;
pub(super) const LINUX_SYSINFO_SYSCALL: u64 = 99;
pub(super) const LINUX_TIMES_SYSCALL: u64 = 100;
pub(super) const LINUX_PTRACE_SYSCALL: u64 = 101;
pub(super) const LINUX_SYSLOG_SYSCALL: u64 = 103;
pub(super) const LINUX_GETUID_SYSCALL: u64 = 102;
pub(super) const LINUX_GETGID_SYSCALL: u64 = 104;
pub(super) const LINUX_SETUID_SYSCALL: u64 = 105;
pub(super) const LINUX_SETGID_SYSCALL: u64 = 106;
pub(super) const LINUX_GETEUID_SYSCALL: u64 = 107;
pub(super) const LINUX_GETEGID_SYSCALL: u64 = 108;
pub(super) const LINUX_SETPGID_SYSCALL: u64 = 109;
pub(super) const LINUX_GETPPID_SYSCALL: u64 = 110;
pub(super) const LINUX_GETPGRP_SYSCALL: u64 = 111;
pub(super) const LINUX_SETSID_SYSCALL: u64 = 112;
pub(super) const LINUX_GETGROUPS_SYSCALL: u64 = 115;
pub(super) const LINUX_SETGROUPS_SYSCALL: u64 = 116;
pub(super) const LINUX_SETREUID_SYSCALL: u64 = 113;
pub(super) const LINUX_SETREGID_SYSCALL: u64 = 114;
pub(super) const LINUX_SETRESUID_SYSCALL: u64 = 117;
pub(super) const LINUX_GETRESUID_SYSCALL: u64 = 118;
pub(super) const LINUX_SETRESGID_SYSCALL: u64 = 119;
pub(super) const LINUX_GETRESGID_SYSCALL: u64 = 120;
pub(super) const LINUX_GETPGID_SYSCALL: u64 = 121;
pub(super) const LINUX_SETFSUID_SYSCALL: u64 = 122;
pub(super) const LINUX_SETFSGID_SYSCALL: u64 = 123;
pub(super) const LINUX_GETSID_SYSCALL: u64 = 124;
pub(super) const LINUX_CAPGET_SYSCALL: u64 = 125;
pub(super) const LINUX_CAPSET_SYSCALL: u64 = 126;
pub(super) const LINUX_SIGALTSTACK_SYSCALL: u64 = 131;
pub(super) const LINUX_UTIME_SYSCALL: u64 = 132;
pub(super) const LINUX_MKNOD_SYSCALL: u64 = 133;
pub(super) const LINUX_USELIB_SYSCALL: u64 = 134;
pub(super) const LINUX_STATFS_SYSCALL: u64 = 137;
pub(super) const LINUX_FSTATFS_SYSCALL: u64 = 138;
pub(super) const LINUX_SYSFS_SYSCALL: u64 = 139;
pub(super) const LINUX_PERSONALITY_SYSCALL: u64 = 135;
pub(super) const LINUX_USTAT_SYSCALL: u64 = 136;
pub(super) const LINUX_GETPRIORITY_SYSCALL: u64 = 140;
pub(super) const LINUX_SETPRIORITY_SYSCALL: u64 = 141;
pub(super) const LINUX_SCHED_SETPARAM_SYSCALL: u64 = 142;
pub(super) const LINUX_SCHED_GETPARAM_SYSCALL: u64 = 143;
pub(super) const LINUX_SCHED_SETSCHEDULER_SYSCALL: u64 = 144;
pub(super) const LINUX_SCHED_GETSCHEDULER_SYSCALL: u64 = 145;
pub(super) const LINUX_SCHED_GET_PRIORITY_MAX_SYSCALL: u64 = 146;
pub(super) const LINUX_SCHED_GET_PRIORITY_MIN_SYSCALL: u64 = 147;
pub(super) const LINUX_SCHED_RR_GET_INTERVAL_SYSCALL: u64 = 148;
pub(super) const LINUX_MLOCK_SYSCALL: u64 = 149;
pub(super) const LINUX_MUNLOCK_SYSCALL: u64 = 150;
pub(super) const LINUX_MLOCKALL_SYSCALL: u64 = 151;
pub(super) const LINUX_MUNLOCKALL_SYSCALL: u64 = 152;
pub(super) const LINUX_VHANGUP_SYSCALL: u64 = 153;
pub(super) const LINUX_SYSCTL_SYSCALL: u64 = 156;
pub(super) const LINUX_ADJTIMEX_SYSCALL: u64 = 159;
pub(super) const LINUX_SETRLIMIT_SYSCALL: u64 = 160;
pub(super) const LINUX_SYNC_SYSCALL: u64 = 162;
pub(super) const LINUX_ACCT_SYSCALL: u64 = 163;
pub(super) const LINUX_SETTIMEOFDAY_SYSCALL: u64 = 164;
pub(super) const LINUX_PRCTL_SYSCALL: u64 = 157;
pub(super) const LINUX_ARCH_PRCTL_SYSCALL: u64 = 158;
pub(super) const LINUX_MODIFY_LDT_SYSCALL: u64 = 154;
pub(super) const LINUX_PIVOT_ROOT_SYSCALL: u64 = 155;
pub(super) const LINUX_CHROOT_SYSCALL: u64 = 161;
pub(super) const LINUX_MOUNT_SYSCALL: u64 = 165;
pub(super) const LINUX_UMOUNT2_SYSCALL: u64 = 166;
pub(super) const LINUX_SHMGET_SYSCALL: u64 = 29;
pub(super) const LINUX_SHMAT_SYSCALL: u64 = 30;
pub(super) const LINUX_SHMCTL_SYSCALL: u64 = 31;
pub(super) const LINUX_SEMGET_SYSCALL: u64 = 64;
pub(super) const LINUX_SEMOP_SYSCALL: u64 = 65;
pub(super) const LINUX_SEMCTL_SYSCALL: u64 = 66;
pub(super) const LINUX_SHMDT_SYSCALL: u64 = 67;
pub(super) const LINUX_MSGGET_SYSCALL: u64 = 68;
pub(super) const LINUX_MSGSND_SYSCALL: u64 = 69;
pub(super) const LINUX_MSGRCV_SYSCALL: u64 = 70;
pub(super) const LINUX_MSGCTL_SYSCALL: u64 = 71;
pub(super) const LINUX_MQ_OPEN_SYSCALL: u64 = 240;
pub(super) const LINUX_MQ_UNLINK_SYSCALL: u64 = 241;
pub(super) const LINUX_MQ_TIMEDSEND_SYSCALL: u64 = 242;
pub(super) const LINUX_MQ_TIMEDRECEIVE_SYSCALL: u64 = 243;
pub(super) const LINUX_MQ_NOTIFY_SYSCALL: u64 = 244;
pub(super) const LINUX_MQ_GETSETATTR_SYSCALL: u64 = 245;
pub(super) const LINUX_SEMTIMEDOP_SYSCALL: u64 = 220;
pub(super) const LINUX_SWAPON_SYSCALL: u64 = 167;
pub(super) const LINUX_SWAPOFF_SYSCALL: u64 = 168;
pub(super) const LINUX_REBOOT_SYSCALL: u64 = 169;
pub(super) const LINUX_SETHOSTNAME_SYSCALL: u64 = 170;
pub(super) const LINUX_SETDOMAINNAME_SYSCALL: u64 = 171;
pub(super) const LINUX_IOPL_SYSCALL: u64 = 172;
pub(super) const LINUX_IOPERM_SYSCALL: u64 = 173;
pub(super) const LINUX_CREATE_MODULE_SYSCALL: u64 = 174;
pub(super) const LINUX_INIT_MODULE_SYSCALL: u64 = 175;
pub(super) const LINUX_DELETE_MODULE_SYSCALL: u64 = 176;
pub(super) const LINUX_GET_KERNEL_SYMS_SYSCALL: u64 = 177;
pub(super) const LINUX_QUERY_MODULE_SYSCALL: u64 = 178;
pub(super) const LINUX_QUOTACTL_SYSCALL: u64 = 179;
pub(super) const LINUX_NFSSERVCTL_SYSCALL: u64 = 180;
pub(super) const LINUX_GETPMSG_SYSCALL: u64 = 181;
pub(super) const LINUX_PUTPMSG_SYSCALL: u64 = 182;
pub(super) const LINUX_AFS_SYSCALL: u64 = 183;
pub(super) const LINUX_TUXCALL_SYSCALL: u64 = 184;
pub(super) const LINUX_SECURITY_SYSCALL: u64 = 185;
pub(super) const LINUX_GETTID_SYSCALL: u64 = 186;
pub(super) const LINUX_READAHEAD_SYSCALL: u64 = 187;
pub(super) const LINUX_SETXATTR_SYSCALL: u64 = 188;
pub(super) const LINUX_LSETXATTR_SYSCALL: u64 = 189;
pub(super) const LINUX_FSETXATTR_SYSCALL: u64 = 190;
pub(super) const LINUX_GETXATTR_SYSCALL: u64 = 191;
pub(super) const LINUX_LGETXATTR_SYSCALL: u64 = 192;
pub(super) const LINUX_FGETXATTR_SYSCALL: u64 = 193;
pub(super) const LINUX_LISTXATTR_SYSCALL: u64 = 194;
pub(super) const LINUX_LLISTXATTR_SYSCALL: u64 = 195;
pub(super) const LINUX_FLISTXATTR_SYSCALL: u64 = 196;
pub(super) const LINUX_REMOVEXATTR_SYSCALL: u64 = 197;
pub(super) const LINUX_LREMOVEXATTR_SYSCALL: u64 = 198;
pub(super) const LINUX_FREMOVEXATTR_SYSCALL: u64 = 199;
pub(super) const LINUX_FUTEX_SYSCALL: u64 = 202;
pub(super) const LINUX_SCHED_SETAFFINITY_SYSCALL: u64 = 203;
pub(super) const LINUX_SCHED_GETAFFINITY_SYSCALL: u64 = 204;
pub(super) const LINUX_SET_THREAD_AREA_SYSCALL: u64 = 205;
pub(super) const LINUX_GET_THREAD_AREA_SYSCALL: u64 = 211;
pub(super) const LINUX_IO_SETUP_SYSCALL: u64 = 206;
pub(super) const LINUX_IO_DESTROY_SYSCALL: u64 = 207;
pub(super) const LINUX_IO_GETEVENTS_SYSCALL: u64 = 208;
pub(super) const LINUX_IO_SUBMIT_SYSCALL: u64 = 209;
pub(super) const LINUX_IO_CANCEL_SYSCALL: u64 = 210;
pub(super) const LINUX_LOOKUP_DCOOKIE_SYSCALL: u64 = 212;
pub(super) const LINUX_GETDENTS64_SYSCALL: u64 = 217;
pub(super) const LINUX_FADVISE64_SYSCALL: u64 = 221;
pub(super) const LINUX_EPOLL_CREATE_SYSCALL: u64 = 213;
pub(super) const LINUX_EPOLL_CTL_OLD_SYSCALL: u64 = 214;
pub(super) const LINUX_EPOLL_WAIT_OLD_SYSCALL: u64 = 215;
pub(super) const LINUX_SET_TID_ADDRESS_SYSCALL: u64 = 218;
pub(super) const LINUX_RESTART_SYSCALL: u64 = 219;
pub(super) const LINUX_TIMER_CREATE_SYSCALL: u64 = 222;
pub(super) const LINUX_TIMER_SETTIME_SYSCALL: u64 = 223;
pub(super) const LINUX_TIMER_GETTIME_SYSCALL: u64 = 224;
pub(super) const LINUX_TIMER_GETOVERRUN_SYSCALL: u64 = 225;
pub(super) const LINUX_TIMER_DELETE_SYSCALL: u64 = 226;
pub(super) const LINUX_CLOCK_GETTIME_SYSCALL: u64 = 228;
pub(super) const LINUX_CLOCK_GETRES_SYSCALL: u64 = 229;
pub(super) const LINUX_CLOCK_NANOSLEEP_SYSCALL: u64 = 230;
pub(super) const LINUX_CLOCK_SETTIME_SYSCALL: u64 = 227;
pub(super) const LINUX_KEXEC_LOAD_SYSCALL: u64 = 246;
pub(super) const LINUX_WAITID_SYSCALL: u64 = 247;
pub(super) const LINUX_ADD_KEY_SYSCALL: u64 = 248;
pub(super) const LINUX_REQUEST_KEY_SYSCALL: u64 = 249;
pub(super) const LINUX_KEYCTL_SYSCALL: u64 = 250;
pub(super) const LINUX_UTIMES_SYSCALL: u64 = 235;
pub(super) const LINUX_VSERVER_SYSCALL: u64 = 236;
pub(super) const LINUX_MBIND_SYSCALL: u64 = 237;
pub(super) const LINUX_SET_MEMPOLICY_SYSCALL: u64 = 238;
pub(super) const LINUX_GET_MEMPOLICY_SYSCALL: u64 = 239;
pub(super) const LINUX_EXIT_GROUP_SYSCALL: u64 = 231;
pub(super) const LINUX_EPOLL_WAIT_SYSCALL: u64 = 232;
pub(super) const LINUX_EPOLL_CTL_SYSCALL: u64 = 233;
pub(super) const LINUX_OPENAT_SYSCALL: u64 = 257;
pub(super) const LINUX_MKDIRAT_SYSCALL: u64 = 258;
pub(super) const LINUX_MKNODAT_SYSCALL: u64 = 259;
pub(super) const LINUX_FCHOWNAT_SYSCALL: u64 = 260;
pub(super) const LINUX_FUTIMESAT_SYSCALL: u64 = 261;
pub(super) const LINUX_RENAMEAT_SYSCALL: u64 = 264;
pub(super) const LINUX_LINKAT_SYSCALL: u64 = 265;
pub(super) const LINUX_NEWFSTATAT_SYSCALL: u64 = 262;
pub(super) const LINUX_UNLINKAT_SYSCALL: u64 = 263;
pub(super) const LINUX_SYMLINKAT_SYSCALL: u64 = 266;
pub(super) const LINUX_READLINKAT_SYSCALL: u64 = 267;
pub(super) const LINUX_FCHMODAT_SYSCALL: u64 = 268;
pub(super) const LINUX_FACCESSAT_SYSCALL: u64 = 269;
pub(super) const LINUX_PSELECT6_SYSCALL: u64 = 270;
pub(super) const LINUX_PPOLL_SYSCALL: u64 = 271;
pub(super) const LINUX_SET_ROBUST_LIST_SYSCALL: u64 = 273;
pub(super) const LINUX_GET_ROBUST_LIST_SYSCALL: u64 = 274;
pub(super) const LINUX_SYNC_FILE_RANGE_SYSCALL: u64 = 277;
pub(super) const LINUX_SPLICE_SYSCALL: u64 = 275;
pub(super) const LINUX_TEE_SYSCALL: u64 = 276;
pub(super) const LINUX_VMSPLICE_SYSCALL: u64 = 278;
pub(super) const LINUX_UNSHARE_SYSCALL: u64 = 272;
pub(super) const LINUX_MIGRATE_PAGES_SYSCALL: u64 = 256;
pub(super) const LINUX_MOVE_PAGES_SYSCALL: u64 = 279;
pub(super) const LINUX_EPOLL_PWAIT_SYSCALL: u64 = 281;
pub(super) const LINUX_UTIMENSAT_SYSCALL: u64 = 280;
pub(super) const LINUX_TIMERFD_CREATE_SYSCALL: u64 = 283;
pub(super) const LINUX_EVENTFD_SYSCALL: u64 = 284;
pub(super) const LINUX_FALLOCATE_SYSCALL: u64 = 285;
pub(super) const LINUX_TIMERFD_SETTIME_SYSCALL: u64 = 286;
pub(super) const LINUX_TIMERFD_GETTIME_SYSCALL: u64 = 287;
pub(super) const LINUX_ACCEPT4_SYSCALL: u64 = 288;
pub(super) const LINUX_EVENTFD2_SYSCALL: u64 = 290;
pub(super) const LINUX_EPOLL_CREATE1_SYSCALL: u64 = 291;
pub(super) const LINUX_DUP3_SYSCALL: u64 = 292;
pub(super) const LINUX_CLONE3_SYSCALL: u64 = 435;
pub(super) const LINUX_OPENAT2_SYSCALL: u64 = 437;
pub(super) const LINUX_OPEN_TREE_SYSCALL: u64 = 428;
pub(super) const LINUX_MOVE_MOUNT_SYSCALL: u64 = 429;
pub(super) const LINUX_FSOPEN_SYSCALL: u64 = 430;
pub(super) const LINUX_FSCONFIG_SYSCALL: u64 = 431;
pub(super) const LINUX_FSMOUNT_SYSCALL: u64 = 432;
pub(super) const LINUX_FSPICK_SYSCALL: u64 = 433;
pub(super) const LINUX_MOUNT_SETATTR_SYSCALL: u64 = 442;
pub(super) const LINUX_OPEN_TREE_ATTR_SYSCALL: u64 = 467;
pub(super) const LINUX_SET_MEMPOLICY_HOME_NODE_SYSCALL: u64 = 450;
pub(super) const LINUX_CACHESTAT_SYSCALL: u64 = 451;
pub(super) const LINUX_PIPE2_SYSCALL: u64 = 293;
pub(super) const LINUX_RT_TGSIGQUEUEINFO_SYSCALL: u64 = 297;
pub(super) const LINUX_RECVMMSG_SYSCALL: u64 = 299;
pub(super) const LINUX_PREADV_SYSCALL: u64 = 295;
pub(super) const LINUX_PWRITEV_SYSCALL: u64 = 296;
pub(super) const LINUX_SENDMMSG_SYSCALL: u64 = 307;
pub(super) const LINUX_COPY_FILE_RANGE_SYSCALL: u64 = 326;
pub(super) const LINUX_PRLIMIT64_SYSCALL: u64 = 302;
pub(super) const LINUX_NAME_TO_HANDLE_AT_SYSCALL: u64 = 303;
pub(super) const LINUX_OPEN_BY_HANDLE_AT_SYSCALL: u64 = 304;
pub(super) const LINUX_GETCPU_SYSCALL: u64 = 309;
pub(super) const LINUX_PROCESS_VM_READV_SYSCALL: u64 = 310;
pub(super) const LINUX_PROCESS_VM_WRITEV_SYSCALL: u64 = 311;
pub(super) const LINUX_KCMP_SYSCALL: u64 = 312;
pub(super) const LINUX_IOPRIO_SET_SYSCALL: u64 = 251;
pub(super) const LINUX_IOPRIO_GET_SYSCALL: u64 = 252;
pub(super) const LINUX_SYNCFS_SYSCALL: u64 = 306;
pub(super) const LINUX_CLOCK_ADJTIME_SYSCALL: u64 = 305;
pub(super) const LINUX_PERF_EVENT_OPEN_SYSCALL: u64 = 298;
pub(super) const LINUX_SETNS_SYSCALL: u64 = 308;
pub(super) const LINUX_FINIT_MODULE_SYSCALL: u64 = 313;
pub(super) const LINUX_KEXEC_FILE_LOAD_SYSCALL: u64 = 320;
pub(super) const LINUX_BPF_SYSCALL: u64 = 321;
pub(super) const LINUX_MEMBARRIER_SYSCALL: u64 = 324;
pub(super) const LINUX_MLOCK2_SYSCALL: u64 = 325;
pub(super) const LINUX_PREADV2_SYSCALL: u64 = 327;
pub(super) const LINUX_PWRITEV2_SYSCALL: u64 = 328;
pub(super) const LINUX_RWF_HIPRI: u64 = 0x01;
pub(super) const LINUX_RWF_DSYNC: u64 = 0x02;
pub(super) const LINUX_RWF_SYNC: u64 = 0x04;
pub(super) const LINUX_RWF_NOWAIT: u64 = 0x08;
pub(super) const LINUX_RWF_APPEND: u64 = 0x10;
pub(super) const LINUX_RWF_NOAPPEND: u64 = 0x20;
pub(super) const LINUX_EXECVEAT_SYSCALL: u64 = 322;
pub(super) const LINUX_MEMFD_CREATE_SYSCALL: u64 = 319;
pub(super) const LINUX_MEMFD_SECRET_SYSCALL: u64 = 447;
pub(super) const LINUX_LANDLOCK_CREATE_RULESET_SYSCALL: u64 = 444;
pub(super) const LINUX_LANDLOCK_ADD_RULE_SYSCALL: u64 = 445;
pub(super) const LINUX_LANDLOCK_RESTRICT_SELF_SYSCALL: u64 = 446;
pub(super) const LINUX_IO_URING_SETUP_SYSCALL: u64 = 425;
pub(super) const LINUX_IO_URING_ENTER_SYSCALL: u64 = 426;
pub(super) const LINUX_IO_URING_REGISTER_SYSCALL: u64 = 427;
pub(super) const LINUX_RSEQ_SYSCALL: u64 = 334;
pub(super) const LINUX_USERFAULTFD_SYSCALL: u64 = 323;
pub(super) const LINUX_URETPROBE_SYSCALL: u64 = 335;
pub(super) const LINUX_SECCOMP_SYSCALL: u64 = 317;
pub(super) const LINUX_IO_PGETEVENTS_SYSCALL: u64 = 333;
pub(super) const LINUX_PKEY_MPROTECT_SYSCALL: u64 = 329;
pub(super) const LINUX_PKEY_ALLOC_SYSCALL: u64 = 330;
pub(super) const LINUX_PKEY_FREE_SYSCALL: u64 = 331;
pub(super) const LINUX_FUTEX_WAKE_SYSCALL: u64 = 454;
pub(super) const LINUX_FUTEX_WAIT_SYSCALL: u64 = 455;
pub(super) const LINUX_FUTEX_REQUEUE_SYSCALL: u64 = 456;
pub(super) const LINUX_MSEAL_SYSCALL: u64 = 462;
pub(super) const LINUX_LSM_GET_SELF_ATTR_SYSCALL: u64 = 459;
pub(super) const LINUX_LSM_SET_SELF_ATTR_SYSCALL: u64 = 460;
pub(super) const LINUX_LSM_LIST_MODULES_SYSCALL: u64 = 461;
pub(super) const LINUX_STATMOUNT_SYSCALL: u64 = 457;
pub(super) const LINUX_LISTMOUNT_SYSCALL: u64 = 458;
pub(super) const LINUX_FUTEX_WAITV_SYSCALL: u64 = 449;
pub(super) const LINUX_PIDFD_SEND_SIGNAL_SYSCALL: u64 = 424;
pub(super) const LINUX_PIDFD_OPEN_SYSCALL: u64 = 434;
pub(super) const LINUX_PIDFD_GETFD_SYSCALL: u64 = 438;
pub(super) const LINUX_PROCESS_MADVISE_SYSCALL: u64 = 440;
pub(super) const LINUX_PROCESS_MRELEASE_SYSCALL: u64 = 448;
pub(super) const LINUX_SIGNALFD_SYSCALL: u64 = 282;
pub(super) const LINUX_SIGNALFD4_SYSCALL: u64 = 289;
pub(super) const LINUX_INOTIFY_INIT_SYSCALL: u64 = 253;
pub(super) const LINUX_INOTIFY_ADD_WATCH_SYSCALL: u64 = 254;
pub(super) const LINUX_INOTIFY_RM_WATCH_SYSCALL: u64 = 255;
pub(super) const LINUX_INOTIFY_INIT1_SYSCALL: u64 = 294;
pub(super) const LINUX_FANOTIFY_INIT_SYSCALL: u64 = 300;
pub(super) const LINUX_FANOTIFY_MARK_SYSCALL: u64 = 301;
pub(super) const LINUX_GETRANDOM_SYSCALL: u64 = 318;
pub(super) const LINUX_STATX_SYSCALL: u64 = 332;
pub(super) const LINUX_RENAMEAT2_SYSCALL: u64 = 316;
pub(super) const LINUX_SCHED_SETATTR_SYSCALL: u64 = 314;
pub(super) const LINUX_SCHED_GETATTR_SYSCALL: u64 = 315;
pub(super) const LINUX_CLOSE_RANGE_SYSCALL: u64 = 436;
pub(super) const LINUX_FACCESSAT2_SYSCALL: u64 = 439;
pub(super) const LINUX_EPOLL_PWAIT2_SYSCALL: u64 = 441;
pub(super) const LINUX_FCHMODAT2_SYSCALL: u64 = 452;
pub(super) const LINUX_MAP_SHADOW_STACK_SYSCALL: u64 = 453;
pub(super) const LINUX_QUOTACTL_FD_SYSCALL: u64 = 443;
pub(super) const LINUX_ARCH_SET_FS: u64 = 0x1002;
pub(super) const LINUX_ARCH_GET_FS: u64 = 0x1003;
pub(super) const LINUX_PROBE_EXIT_STATUS: u64 = 42;
pub(super) const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
pub(super) const LINUX_CAPABILITY_DATA_SIZE: usize = 24;
pub(super) const LINUX_RETURN_TO_KERNEL: u64 = (-4096_i64) as u64;
/// The length of the `syscall` instruction, for restarting a syscall.
pub(super) const LINUX_SYSCALL_INSTRUCTION_SIZE: u64 = 2;
pub(super) const LINUX_RETURN_FROM_IRET: u64 = (-4095_i64) as u64;
pub(super) const LINUX_EPERM: u64 = u64::MAX;
pub(super) const LINUX_EIO: u64 = u64::MAX - 4;
pub(super) const LINUX_ENXIO: u64 = u64::MAX - 5;
pub(super) const LINUX_EINTR: u64 = u64::MAX - 3;
pub(super) const LINUX_E2BIG: u64 = u64::MAX - 6;
pub(super) const LINUX_ENOEXEC: u64 = u64::MAX - 7;
pub(super) const LINUX_EBADF: u64 = u64::MAX - 8;
pub(super) const LINUX_ENOENT: u64 = u64::MAX - 1;
pub(super) const LINUX_ESRCH: u64 = u64::MAX - 2;
pub(super) const LINUX_ECHILD: u64 = u64::MAX - 9;
pub(super) const LINUX_EFAULT: u64 = u64::MAX - 13;
pub(super) const LINUX_EAGAIN: u64 = u64::MAX - 10;
pub(super) const LINUX_EPIPE: u64 = u64::MAX - 31;
pub(super) const LINUX_EACCES: u64 = u64::MAX - 12;
pub(super) const LINUX_EBUSY: u64 = u64::MAX - 15;
/// Not a block device: mounting a filesystem from anything else.
pub(super) const LINUX_ENOTBLK: u64 = u64::MAX - 14;
/// A program being run cannot be written, nor a file open for writing run.
pub(super) const LINUX_ETXTBSY: u64 = u64::MAX - 25;
pub(super) const LINUX_ECONNREFUSED: u64 = u64::MAX - 110;
pub(super) const LINUX_F_SETPIPE_SZ: u64 = 1031;
pub(super) const LINUX_F_GETPIPE_SZ: u64 = 1032;
/// /proc/sys/fs/pipe-max-size: the largest pipe an unprivileged process may ask for.
pub(super) const LINUX_PIPE_MAX_SIZE: u64 = 1_048_576;
pub(super) const LINUX_EEXIST: u64 = u64::MAX - 16;
pub(super) const LINUX_EXDEV: u64 = u64::MAX - 17;
pub(super) const LINUX_ENODEV: u64 = u64::MAX - 18;
pub(super) const LINUX_ENOTDIR: u64 = u64::MAX - 19;
pub(super) const LINUX_EISDIR: u64 = u64::MAX - 20;
pub(super) const LINUX_ENOMEM: u64 = u64::MAX - 11;
pub(super) const LINUX_ENOSPC: u64 = u64::MAX - 27;
pub(super) const LINUX_EFBIG: u64 = u64::MAX - 26;
pub(super) const LINUX_ESPIPE: u64 = u64::MAX - 28;
pub(super) const LINUX_EMFILE: u64 = u64::MAX - 23;
pub(super) const LINUX_EINVAL: u64 = u64::MAX - 21;
pub(super) const LINUX_ENOTTY: u64 = u64::MAX - 24;
/// Too many users: setns into a time namespace from a threaded process.
pub(super) const LINUX_EUSERS: u64 = u64::MAX - 86;
pub(super) const LINUX_ERANGE: u64 = u64::MAX - 33;
pub(super) const LINUX_EDOM: u64 = u64::MAX - 32;
pub(super) const LINUX_ENOLCK: u64 = u64::MAX - 36;
pub(super) const LINUX_EDEADLK: u64 = u64::MAX - 34;
pub(super) const LINUX_ENOMSG: u64 = u64::MAX - 41;
/// "File descriptor in bad state": a descriptor of the wrong kind for a
/// Landlock call.
pub(super) const LINUX_EBADFD: u64 = u64::MAX - 76;
pub(super) const LINUX_EIDRM: u64 = u64::MAX - 42;
pub(super) const LINUX_EOVERFLOW: u64 = u64::MAX - 74;
pub(super) const LINUX_ELOOP: u64 = u64::MAX - 39;
/// The longest pathname a system call takes, terminator included (PATH_MAX).
pub(super) const LINUX_PATH_MAX: usize = 4096;
pub(super) const LINUX_ESTALE: u64 = u64::MAX - 115;
/// Not an errno: an open or truncate waits for a lease to be broken
/// (`linux_lease_live_return` retries it; it never reaches the caller).
pub(super) const LINUX_LEASE_PENDING: u64 = u64::MAX - 700;
pub(super) const LINUX_ENOKEY: u64 = u64::MAX - 125;
pub(super) const LINUX_EKEYREVOKED: u64 = u64::MAX - 127;
pub(super) const LINUX_ENODATA: u64 = u64::MAX - 60;
pub(super) const LINUX_EMSGSIZE: u64 = u64::MAX - 89;
pub(super) const LINUX_ENOTSOCK: u64 = u64::MAX - 87;
pub(super) const LINUX_EOPNOTSUPP: u64 = u64::MAX - 94;
pub(super) const LINUX_ECANCELED: u64 = u64::MAX - 124;
pub(super) const LINUX_ENAMETOOLONG: u64 = u64::MAX - 35;
pub(super) const LINUX_ENOSYS: u64 = u64::MAX - 37;
pub(super) const LINUX_ENOTEMPTY: u64 = u64::MAX - 38;
pub(super) const LINUX_EROFS: u64 = u64::MAX - 29;
pub(super) const LINUX_ETIMEDOUT: u64 = u64::MAX - 109;
pub(super) const LINUX_ETOOMANYREFS: u64 = u64::MAX - 108;
pub(super) const LINUX_ECONNRESET: u64 = u64::MAX - 103;
pub(super) const LINUX_ENOTCONN: u64 = u64::MAX - 106;
pub(super) const LINUX_EISCONN: u64 = u64::MAX - 105;
pub(super) const LINUX_EALREADY: u64 = u64::MAX - 113;
pub(super) const LINUX_EINPROGRESS: u64 = u64::MAX - 114;
pub(super) const LINUX_EAFNOSUPPORT: u64 = u64::MAX - 96;
pub(super) const LINUX_ESOCKTNOSUPPORT: u64 = u64::MAX - 93;
pub(super) const LINUX_EPROTONOSUPPORT: u64 = u64::MAX - 92;
pub(super) const LINUX_ENOPROTOOPT: u64 = u64::MAX - 91;
pub(super) const LINUX_EPROTOTYPE: u64 = u64::MAX - 90;
pub(super) const LINUX_ENETUNREACH: u64 = u64::MAX - 100;
pub(super) const LINUX_ENFILE: u64 = u64::MAX - 22;
pub(super) const LINUX_EADDRINUSE: u64 = u64::MAX - 97;
pub(super) const LINUX_EADDRNOTAVAIL: u64 = u64::MAX - 98;
pub(super) const LINUX_XATTR_CREATE: u64 = 1;
pub(super) const LINUX_XATTR_REPLACE: u64 = 2;
pub(super) const LINUX_XATTR_SIZE_MAX: usize = 65_536;
pub(super) const LINUX_UTIME_NOW: i64 = 1_073_741_823;
pub(super) const LINUX_UTIME_OMIT: i64 = 1_073_741_822;
pub(super) const LINUX_RLIMIT_FSIZE: u64 = 1;
pub(super) const LINUX_RLIMIT_STACK: u64 = 3;
pub(super) const LINUX_RLIMIT_NPROC: u64 = 6;
pub(super) const LINUX_RLIMIT_NOFILE: u64 = 7;
pub(super) const LINUX_RLIMIT_MEMLOCK: u64 = 8;
/// /proc/sys/fs/nr_open: the most RLIMIT_NOFILE may be raised to.
pub(super) const LINUX_NR_OPEN: u64 = 1_048_576;
pub(super) const LINUX_RLIMIT_AS: u64 = 9;
pub(super) const LINUX_RLIMIT_SIGPENDING: u64 = 11;
pub(super) const LINUX_RLIMIT_MSGQUEUE: u64 = 12;
pub(super) const LINUX_RLIMIT_NLIMITS: u64 = 16;
pub(super) const LINUX_RLIMIT_WORDS: usize = LINUX_RLIMIT_NLIMITS as usize * 2;
pub(super) const LINUX_WNOHANG: u64 = 1;
pub(super) const LINUX_WUNTRACED: u64 = 2;
pub(super) const LINUX_WEXITED: u64 = 4;
pub(super) const LINUX_WCONTINUED: u64 = 8;
pub(super) const LINUX_WNOWAIT: u64 = 0x0100_0000;
pub(super) const LINUX_P_ALL: u64 = 0;
pub(super) const LINUX_P_PID: u64 = 1;
pub(super) const LINUX_P_PGID: u64 = 2;
pub(super) const LINUX_P_PIDFD: u64 = 3;
pub(super) const LINUX_MSG_ERRQUEUE: u64 = 0x2000;
pub(super) const LINUX_CLD_EXITED: i32 = 1;
pub(super) const LINUX_CLD_KILLED: i32 = 2;
pub(super) const LINUX_CLD_STOPPED: i32 = 5;
pub(super) const LINUX_CLD_CONTINUED: i32 = 6;
pub(super) const LINUX_RUSAGE_SIZE: usize = 144;
pub(super) const LINUX_PROT_READ: u64 = 1;
pub(super) const LINUX_PROT_WRITE: u64 = 2;
pub(super) const LINUX_PROT_EXEC: u64 = 4;
pub(super) const LINUX_MAP_SHARED: u64 = 1;
pub(super) const LINUX_MAP_PRIVATE: u64 = 2;
/// Private anonymous memory the kernel may drop under memory pressure.
pub(super) const LINUX_MAP_DROPPABLE: u64 = 0x08;
/// The bits of mmap's flags that give the mapping's type.
pub(super) const LINUX_MAP_TYPE: u64 = 0x0f;
pub(super) const LINUX_MAP_FIXED: u64 = 0x10;
pub(super) const LINUX_MAP_SHARED_VALIDATE: u64 = 0x3;
pub(super) const LINUX_MAP_32BIT: u64 = 0x40;
pub(super) const LINUX_MAP_ANONYMOUS: u64 = 0x20;
pub(super) const LINUX_MAP_EXECUTABLE: u64 = 0x1000;
pub(super) const LINUX_MAP_LOCKED: u64 = 0x2000;
pub(super) const LINUX_MAP_NORESERVE: u64 = 0x4000;
pub(super) const LINUX_MAP_GROWSDOWN: u64 = 0x100;
pub(super) const LINUX_MAP_DENYWRITE: u64 = 0x800;
pub(super) const LINUX_MAP_POPULATE: u64 = 0x8000;
pub(super) const LINUX_MAP_NONBLOCK: u64 = 0x1_0000;
pub(super) const LINUX_MAP_STACK: u64 = 0x2_0000;
pub(super) const LINUX_MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
pub(super) const LINUX_MAIN_MAPPING_COUNT: usize = 8;
pub(super) const LINUX_DEPENDENCY_MAPPING_COUNT: usize = 8;
pub(super) const LINUX_DEPENDENCY_COUNT: usize = 2;
pub(super) const LINUX_DEPENDENCY_STATE_COUNT: usize =
    LINUX_DEPENDENCY_COUNT * LINUX_DEPENDENCY_MAPPING_COUNT;
pub(super) const LINUX_MADV_DONTNEED: u64 = 4;
pub(super) const LINUX_MADV_FREE: u64 = 8;
pub(super) const LINUX_MADV_NORMAL: u64 = 0;
pub(super) const LINUX_MADV_RANDOM: u64 = 1;
pub(super) const LINUX_MADV_SEQUENTIAL: u64 = 2;
pub(super) const LINUX_MADV_WILLNEED: u64 = 3;
pub(super) const LINUX_MADV_DONTFORK: u64 = 10;
pub(super) const LINUX_MADV_DOFORK: u64 = 11;
pub(super) const LINUX_MADV_MERGEABLE: u64 = 12;
pub(super) const LINUX_MADV_UNMERGEABLE: u64 = 13;
pub(super) const LINUX_MADV_HUGEPAGE: u64 = 14;
pub(super) const LINUX_MADV_NOHUGEPAGE: u64 = 15;
pub(super) const LINUX_MADV_DONTDUMP: u64 = 16;
pub(super) const LINUX_MADV_DODUMP: u64 = 17;
pub(super) const LINUX_MADV_WIPEONFORK: u64 = 18;
pub(super) const LINUX_MADV_KEEPONFORK: u64 = 19;
pub(super) const LINUX_MADV_COLD: u64 = 20;
pub(super) const LINUX_MADV_PAGEOUT: u64 = 21;
pub(super) const LINUX_MADV_POPULATE_READ: u64 = 22;
pub(super) const LINUX_MADV_POPULATE_WRITE: u64 = 23;
pub(super) const LINUX_MADV_DONTNEED_LOCKED: u64 = 24;
pub(super) const LINUX_MADV_SOFT_OFFLINE: u64 = 101;
/// madvise(MADV_HWPOISON): the pages act as if their memory failed.
pub(super) const LINUX_MADV_HWPOISON: u64 = 100;
pub(super) const LINUX_STAT_SIZE: usize = 144;
pub(super) const LINUX_STAT_CHARACTER_DEVICE_MODE: u32 = 0o020600;
pub(super) const LINUX_STAT_DIRECTORY_MODE: u32 = 0o040555;
pub(super) const LINUX_STAT_REGULAR_MODE: u32 = 0o100555;
pub(super) const LINUX_STAT_FIFO_MODE: u32 = 0o010600;
pub(super) const LINUX_STAT_SOCKET_MODE: u32 = 0o140600;
pub(super) const LINUX_STAT_ANONYMOUS_MODE: u32 = 0o600;
pub(super) const LINUX_STATX_BASIC_STATS: u32 = 0x7ff;
pub(super) const LINUX_STATX_MNT_ID: u32 = 0x1000;
pub(super) const LINUX_STATX_RESERVED: u32 = 0x8000_0000;
pub(super) const LINUX_WRITE_LIMIT: usize = PAGE_SIZE;
pub(super) const LINUX_IOV_LIMIT: usize = 64;
pub(super) const LINUX_POLLFD_LIMIT: usize = 64;
pub(super) const LINUX_AUX_DESCRIPTOR_FIRST: u64 = 3;
pub(super) const LINUX_AUX_DESCRIPTOR_LIMIT: u64 = 1024;
pub(super) const LINUX_SELECT_WORD_LIMIT: usize =
    LINUX_AUX_DESCRIPTOR_LIMIT as usize / u64::BITS as usize;
pub(super) const LINUX_DESCRIPTOR_TABLE_LIMIT: u64 = 1024;
pub(super) const LINUX_DEVICE_DESCRIPTOR_COUNT: usize =
    LINUX_DESCRIPTOR_TABLE_LIMIT as usize - LINUX_AUX_DESCRIPTOR_FIRST as usize;
pub(super) const LINUX_DESCRIPTOR_FLAG_WORD_COUNT: usize =
    LINUX_DESCRIPTOR_TABLE_LIMIT.div_ceil(u64::BITS as u64) as usize;
pub(super) const LINUX_POLLIN: u16 = 1;
/// Urgent or exceptional data (a /proc/mounts change).
pub(super) const LINUX_POLLPRI: u16 = 2;
pub(super) const LINUX_POLLRDNORM: u16 = 0x40;
pub(super) const LINUX_POLLOUT: u16 = 4;
pub(super) const LINUX_POLLERR: u16 = 8;
pub(super) const LINUX_POLLHUP: u16 = 0x10;
/// The peer shut down writing, or reading was shut down (EPOLLRDHUP).
pub(super) const LINUX_POLLRDHUP: u16 = 0x2000;
pub(super) const LINUX_POLLNVAL: u16 = 0x20;
pub(super) const LINUX_EPOLL_CTL_ADD: u64 = 1;
pub(super) const LINUX_EPOLL_CTL_DEL: u64 = 2;
pub(super) const LINUX_EPOLL_CTL_MOD: u64 = 3;
pub(super) const LINUX_EPOLL_SUPPORTED_EVENTS: u32 =
    (LINUX_POLLIN | LINUX_POLLOUT | LINUX_POLLERR | LINUX_POLLHUP) as u32
        | 0x0000_0002
        | 0x0000_0040
        | 0x0000_0080
        | 0x0000_0100
        | 0x0000_0200
        | 0x0000_0400
        | 0x0000_2000
        | 0x1000_0000
        | 0x2000_0000
        | 0x4000_0000
        | 0x8000_0000;
pub(super) const LINUX_EPOLLET: u32 = 0x8000_0000;
pub(super) const LINUX_EPOLLONESHOT: u32 = 0x4000_0000;
/// One event wakes one of the epoll instances watching a file this way.
pub(super) const LINUX_EPOLLEXCLUSIVE: u32 = 0x1000_0000;
/// What an EPOLLEXCLUSIVE watch may ask for (Linux's EPOLLEXCLUSIVE_OK_BITS):
/// in, out, error, hangup, EPOLLWAKEUP, EPOLLET and itself.
pub(super) const LINUX_EPOLLEXCLUSIVE_OK_BITS: u32 =
    (LINUX_POLLIN | LINUX_POLLOUT | LINUX_POLLERR | LINUX_POLLHUP) as u32
        | 0x2000_0000
        | LINUX_EPOLLET
        | LINUX_EPOLLEXCLUSIVE;
pub(super) const LINUX_EFD_SEMAPHORE: u64 = 1;
pub(super) const LINUX_EFD_NONBLOCK: u64 = 0x800;
pub(super) const LINUX_TFD_TIMER_ABSTIME: u64 = 1;
pub(super) const LINUX_TIMER_ABSTIME: u64 = 1;
pub(super) const LINUX_TFD_NONBLOCK: u64 = 0x800;
pub(super) const LINUX_PIPE_CAPACITY: usize = 256;
pub(super) const LINUX_PIPE_READV_WAIT_FLAG: u64 = 1 << 63;
pub(super) const LINUX_PIPE_WRITEV_WAIT_FLAG: u64 = 1 << 63;
pub(super) const LINUX_AT_FDCWD: u32 = (-100_i32) as u32;
pub(super) const LINUX_AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub(super) const LINUX_AT_REMOVEDIR: u64 = 0x200;
pub(super) const LINUX_AT_EACCESS: u64 = 0x200;
pub(super) const LINUX_AT_NO_AUTOMOUNT: u64 = 0x800;
pub(super) const LINUX_AT_EMPTY_PATH: u64 = 0x1000;
pub(super) const LINUX_AT_STATX_SYNC_TYPE: u64 = 0x6000;
pub(super) const LINUX_TCGETS: u64 = 0x5401;
pub(super) const LINUX_TCSETS: u64 = 0x5402;
pub(super) const LINUX_TCSETSW: u64 = 0x5403;
pub(super) const LINUX_TCSETSF: u64 = 0x5404;
/// The termios2 forms (`struct termios2`: termios and input and output
/// speeds), which Rust's rustix uses.
pub(super) const LINUX_TCGETS2: u64 = 0x802c_542a;
pub(super) const LINUX_TCSETS2: u64 = 0x402c_542b;
pub(super) const LINUX_TCSETSW2: u64 = 0x402c_542c;
pub(super) const LINUX_TCSETSF2: u64 = 0x402c_542d;
pub(super) const LINUX_TIOCSCTTY: u64 = 0x540e;
pub(super) const LINUX_TIOCGPGRP: u64 = 0x540f;
pub(super) const LINUX_TIOCSPGRP: u64 = 0x5410;
pub(super) const LINUX_TIOCGWINSZ: u64 = 0x5413;
pub(super) const LINUX_TIOCNOTTY: u64 = 0x5422;
pub(super) const LINUX_TIOCGSID: u64 = 0x5429;
pub(super) const LINUX_TIOCVHANGUP: u64 = 0x5437;
pub(super) const LINUX_FIONREAD: u64 = 0x541b;
pub(super) const LINUX_FIONBIO: u64 = 0x5421;
pub(super) const LINUX_FIONCLEX: u64 = 0x5450;
pub(super) const LINUX_FIOCLEX: u64 = 0x5451;
pub(super) const LINUX_FIOASYNC: u64 = 0x5452;
pub(super) const LINUX_DESCRIPTOR_INPUT: u16 = 1;
pub(super) const LINUX_DESCRIPTOR_OUTPUT: u16 = 2;
pub(super) const LINUX_DEVICE_ZERO: u16 = 1 << 2;
/// /dev/urandom and /dev/random: the zero bit with one of the anonymous
/// file bits, which those kinds only ever use alone (compared exactly).
pub(super) const LINUX_DEVICE_RANDOM: u16 = LINUX_DEVICE_ZERO | 1 << 8;
/// /dev/full, encoded as LINUX_DEVICE_RANDOM is.
pub(super) const LINUX_DEVICE_FULL: u16 = LINUX_DEVICE_ZERO | 1 << 9;
pub(super) const LINUX_DEVICE_CONSOLE: u16 = 1 << 3;
pub(super) const LINUX_DEVICE_DIRECTORY: u16 = 1 << 4;
pub(super) const LINUX_DEVICE_FANOTIFY: u16 = 1 << 9;
pub(super) const LINUX_DEVICE_POSIX_MQ: u16 = 1 << 10;
pub(super) const LINUX_DEVICE_INOTIFY: u16 = 1 << 11;
pub(super) const LINUX_DEVICE_PIDFD: u16 = 1 << 13;
pub(super) const LINUX_DEVICE_SIGNALFD: u16 = 1 << 12;
/// A /proc/PID/ns descriptor (nsfs): the pidfd and signalfd bits together,
/// which those kinds only ever use alone (compared exactly).
pub(super) const LINUX_DEVICE_NAMESPACE: u16 = LINUX_DEVICE_PIDFD | LINUX_DEVICE_SIGNALFD;
pub(super) const LINUX_DEVICE_PIPE: u16 = 1 << 14;
pub(super) const LINUX_DEVICE_SOCKET: u16 = 1 << 15;
pub(super) const LINUX_FILE_INIT: u16 = 1 << 5;
pub(super) const LINUX_FILE_INTERPRETER: u16 = 1 << 6;
pub(super) const LINUX_FILE_DEPENDENCY: u16 = 1 << 7;
pub(super) const LINUX_FILE_AUXILIARY_DEPENDENCY: u16 =
    LINUX_FILE_INTERPRETER | LINUX_FILE_DEPENDENCY;
pub(super) const LINUX_FILE_ROOT_HOSTNAME: u16 = LINUX_FILE_INIT | LINUX_FILE_INTERPRETER;
pub(super) const LINUX_FILE_ROOT_GENERIC: u16 = LINUX_FILE_INIT | LINUX_FILE_DEPENDENCY;
pub(super) const LINUX_ROOT_MEASURED_DIRECTORY: u16 = LINUX_DEVICE_DIRECTORY | LINUX_FILE_INIT;
pub(super) const LINUX_ROOT_DIRECTORY: u16 = LINUX_DEVICE_DIRECTORY | LINUX_FILE_INTERPRETER;
pub(super) const LINUX_FILE_MASK: u16 =
    LINUX_FILE_INIT | LINUX_FILE_INTERPRETER | LINUX_FILE_DEPENDENCY;
pub(super) const LINUX_FILE_PROC_STATUS: u16 = LINUX_FILE_MASK;
pub(super) const LINUX_PROC_PID1_DIRECTORY: u16 = LINUX_DEVICE_DIRECTORY | LINUX_FILE_PROC_STATUS;
pub(super) const LINUX_PROC_PID2_DIRECTORY_NODE: u16 = 0xfa00;
pub(super) const LINUX_PROC_PID2_DIRECTORY: u16 =
    LINUX_DEVICE_DIRECTORY | LINUX_FILE_PROC_STATUS | LINUX_PROC_PID2_DIRECTORY_NODE;
pub(super) const LINUX_PROC_FD_DIRECTORY_NODE: u16 = 0xed00;
pub(super) const LINUX_PROC_FD_DIRECTORY: u16 =
    LINUX_DEVICE_DIRECTORY | LINUX_FILE_PROC_STATUS | LINUX_PROC_FD_DIRECTORY_NODE;
pub(super) const LINUX_PROC_PID2_STATUS_NODE: u16 = 0xf900;
pub(super) const LINUX_FILE_PROC_PID2_STATUS: u16 = LINUX_FILE_MASK | LINUX_PROC_PID2_STATUS_NODE;
pub(super) const LINUX_PROC_MOUNTS_NODE: u16 = 0xdd00;
pub(super) const LINUX_FILE_PROC_MOUNTS: u16 = LINUX_FILE_MASK | LINUX_PROC_MOUNTS_NODE;
/// `/proc/sysrq-trigger`: writing `t` lists every task to the kernel log.
pub(super) const LINUX_PROC_SYSRQ_TRIGGER_NODE: u16 = 0xdc00;
pub(super) const LINUX_FILE_PROC_SYSRQ_TRIGGER: u16 =
    LINUX_FILE_MASK | LINUX_PROC_SYSRQ_TRIGGER_NODE;
/// `/proc/sysvipc/msg`, `shm` and `sem`: the domain's System V IPC objects,
/// a header line then one line each (LTP counts the lines).
pub(super) const LINUX_PROC_SYSVIPC_MSG_NODE: u16 = 0xcd00;
pub(super) const LINUX_FILE_PROC_SYSVIPC_MSG: u16 = LINUX_FILE_MASK | LINUX_PROC_SYSVIPC_MSG_NODE;
pub(super) const LINUX_PROC_SYSVIPC_SHM_NODE: u16 = 0xce00;
pub(super) const LINUX_FILE_PROC_SYSVIPC_SHM: u16 = LINUX_FILE_MASK | LINUX_PROC_SYSVIPC_SHM_NODE;
pub(super) const LINUX_PROC_SYSVIPC_SEM_NODE: u16 = 0xcf00;
pub(super) const LINUX_FILE_PROC_SYSVIPC_SEM: u16 = LINUX_FILE_MASK | LINUX_PROC_SYSVIPC_SEM_NODE;
/// `/proc/PID/task`: a process's threads by id, each a directory of the
/// process's files, and `/proc/PID/task/TID/comm`, the thread's name.
pub(super) const LINUX_PROC_TASK_DIRECTORY_NODE: u16 = 0xb600;
pub(super) const LINUX_PROC_TASK_DIRECTORY: u16 =
    LINUX_DEVICE_DIRECTORY | LINUX_FILE_PROC_STATUS | LINUX_PROC_TASK_DIRECTORY_NODE;
pub(super) const LINUX_PROC_TASK_COMM_NODE: u16 = 0xb700;
pub(super) const LINUX_FILE_PROC_TASK_COMM: u16 = LINUX_FILE_MASK | LINUX_PROC_TASK_COMM_NODE;
/// `/proc/PID/task/TID/stat`: the thread's stat line, its id first and its
/// own state (its descriptor keeps the thread id).
pub(super) const LINUX_PROC_TASK_STAT_NODE: u16 = 0xb800;
pub(super) const LINUX_FILE_PROC_TASK_STAT: u16 = LINUX_FILE_MASK | LINUX_PROC_TASK_STAT_NODE;
/// `/proc/sys` values are numbered from their place in
/// `LINUX_PROC_SYSCTLS`, in a node range of their own below the /proc/sys
/// directories' (`LINUX_PROC_SYSCTL_FIRST_NODE` up to
/// `LINUX_PROC_SYS_DIRECTORY_FIRST_NODE`): the table grows to 111 values
/// without taking another /proc file's node or picking numbers by hand.
pub(super) const LINUX_PROC_SYSCTL_FIRST_NODE: u16 = 0x0100;

/// `values` (path under `/proc`, contents) with the nodes their places give.
const fn linux_numbered_sysctls<const N: usize>(
    values: [(&'static [u8], &'static [u8]); N],
) -> [(u16, &'static [u8], &'static [u8]); N] {
    assert!(
        LINUX_PROC_SYSCTL_FIRST_NODE as usize + (N << 8)
            <= LINUX_PROC_SYS_DIRECTORY_FIRST_NODE as usize
    );
    let mut numbered: [(u16, &'static [u8], &'static [u8]); N] = [(0, &[], &[]); N];
    let mut index = 0;
    while index < N {
        numbered[index] = (
            LINUX_PROC_SYSCTL_FIRST_NODE + ((index as u16) << 8),
            values[index].0,
            values[index].1,
        );
        index += 1;
    }
    numbered
}

/// The node of the `/proc/sys` value at `path` (under `/proc`).
const fn linux_proc_sysctl_node_named(path: &[u8]) -> u16 {
    let mut index = 0;
    while index < LINUX_PROC_SYSCTLS.len() {
        let (node, name, _) = LINUX_PROC_SYSCTLS[index];
        if name.len() == path.len() {
            let mut byte = 0;
            while byte < path.len() && name[byte] == path[byte] {
                byte += 1;
            }
            if byte == path.len() {
                return node;
            }
        }
        index += 1;
    }
    panic!("no such /proc/sys value")
}

/// `/proc/sys` values: node, path under `/proc`, contents. Values match
/// what Ginux implements (four user namespaces); root may write them, and
/// the kernel acts on those it reads back (`linux_proc_sysctl_value`).
/// `/proc/sys/fs/aio-max-nr`: the most events one io_setup context may hold.
pub(super) const LINUX_AIO_MAX_NR: u64 = 65_536;
/// `/proc/sys/vm/max_map_count`: the most memory areas a process may have.
pub(super) const LINUX_MAX_MAP_COUNT: usize = 65_530;
// threads-max below is linux_process::PROCESS_LIMIT.
const _: () = assert!(crate::linux_process::PROCESS_LIMIT == 4096);
pub(super) const LINUX_PROC_SYSCTLS: [(u16, &[u8], &[u8]); 64] = linux_numbered_sysctls([
    // The most memory areas a process may have (LINUX_MAX_MAP_COUNT).
    (b"sys/vm/max_map_count", b"65530\n"),
    // Writing 1, 2 or 3 drops the volumes' page caches (linux_blockfs);
    // it reads as the last value written.
    (b"sys/vm/drop_caches", b"0\n"),
    // The huge page pool (`linux_hugetlb`): its persistent pages, which a
    // write sets as far as free memory goes, the surplus pages it may lend
    // beyond them, and the group whose members may make SHM_HUGETLB
    // segments.
    (b"sys/vm/nr_hugepages", b"0\n"),
    (b"sys/vm/nr_overcommit_hugepages", b"0\n"),
    (b"sys/vm/hugetlb_shm_group", b"0\n"),
    // How hard the kernel reclaims the dentry and inode caches; Ginux keeps
    // the value (tests save and restore it).
    (b"sys/vm/vfs_cache_pressure", b"100\n"),
    // The reserve below which allocations must reclaim. Ginux has no
    // watermarks; the value is the one Linux picks for 4 GiB
    // (sqrt(lowmem KiB * 16)), kept when written. Memory tests read it to
    // leave that much free.
    (b"sys/vm/min_free_kbytes", b"8192\n"),
    // How readily reclaim pages anonymous memory out to swap rather than
    // dropping caches (0 to 200); Ginux keeps the value.
    (b"sys/vm/swappiness", b"60\n"),
    // The random pool is always full, as Linux reports it since 5.18.
    (b"sys/kernel/random/entropy_avail", b"256\n"),
    (b"sys/kernel/random/poolsize", b"256\n"),
    // Core files are "core" in the dumping process's directory.
    (b"sys/kernel/core_pattern", b"core\n"),
    (b"sys/kernel/core_uses_pid", b"0\n"),
    // Console log levels (syslog's CONSOLE_LEVEL; syslog11 saves them).
    (b"sys/kernel/printk", b"7\t4\t1\t7\n"),
    // System V IPC limits, Linux's defaults; tests read them to size runs.
    (b"sys/kernel/shmmni", b"4096\n"),
    (b"sys/kernel/shmmax", b"18446744073692774399\n"),
    (b"sys/kernel/shmall", b"18446744073692774399\n"),
    (b"sys/kernel/msgmax", b"8192\n"),
    (b"sys/kernel/msgmnb", b"16384\n"),
    (
        b"sys/kernel/sem",
        // SEMMSL, SEMMNS, SEMOPM, SEMMNI: sets are a frame each here, so
        // the count is bounded at 1024 (linux_sysv_ipc::SEMAPHORE_SET_LIMIT).
        b"32000\t1024000000\t500\t1024\n",
    ),
    // uname's fields, as /proc/sys/kernel shows them (linux_time::linux_uname).
    (b"sys/kernel/ostype", b"Linux\n"),
    (b"sys/kernel/version", b"#1\n"),
    (b"sys/kernel/domainname", b"localdomain\n"),
    // The id the next created queue or segment gets once written (-1: the
    // next free one); the kernel resets it to -1 when it uses it.
    (b"sys/kernel/msg_next_id", b"-1\n"),
    (b"sys/kernel/shm_next_id", b"-1\n"),
    (b"sys/kernel/pid_max", b"4194304\n"),
    // Who may make io_uring rings: 0 everyone, 1 CAP_SYS_ADMIN, 2 nobody.
    (b"sys/kernel/io_uring_disabled", b"0\n"),
    (b"sys/kernel/tainted", b"0\n"),
    // perf_event_open (cpu/linux_perf.rs): who may count what (2: a task's
    // user-space work without CAP_PERFMON), the highest sampling rate, the
    // locked buffer size per user and the deepest call chain.
    (b"sys/kernel/perf_event_paranoid", b"2\n"),
    (b"sys/kernel/perf_event_max_sample_rate", b"100000\n"),
    (b"sys/kernel/perf_event_mlock_kb", b"516\n"),
    (b"sys/kernel/perf_event_max_stack", b"127\n"),
    (b"sys/user/max_user_namespaces", b"3\n"),
    (b"sys/fs/pipe-max-size", b"1048576\n"),
    (b"sys/fs/aio-max-nr", b"65536\n"),
    // The most descriptors a process may have (LINUX_NR_OPEN); unsharing a
    // descriptor table holding one above it fails (unshare03).
    (b"sys/fs/nr_open", b"1048576\n"),
    // IPv4 interface tags (devconf "tag"), which each network namespace
    // has its own of (clone09): every interface's, new ones', the loopback's.
    (b"sys/net/ipv4/conf/all/tag", b"0\n"),
    (b"sys/net/ipv4/conf/default/tag", b"0\n"),
    (b"sys/net/ipv4/conf/lo/tag", b"0\n"),
    // The groups that may make ping sockets (ICMP and ICMPv6 SOCK_DGRAM),
    // a pair of gids, each network namespace's own; every group may, as
    // systemd-based distributions set it (Linux's own default, "1 0", lets
    // none).
    (LINUX_PING_GROUP_RANGE, b"0\t2147483647\n"),
    (b"sys/fs/pipe-user-pages-soft", b"16384\n"),
    // Seconds a lease holder has to give up its lease (fcntl33 saves it).
    (b"sys/fs/lease-break-time", b"45\n"),
    // POSIX message queue limits (mq_open): the queues a domain may hold,
    // the largest attributes an unprivileged process may ask for, and what
    // a queue gets without attributes.
    (b"sys/fs/mqueue/queues_max", b"256\n"),
    (b"sys/fs/mqueue/msg_max", b"10\n"),
    (b"sys/fs/mqueue/msgsize_max", b"8192\n"),
    (b"sys/fs/mqueue/msg_default", b"10\n"),
    (b"sys/fs/mqueue/msgsize_default", b"8192\n"),
    // Values tests read to size themselves.
    (b"sys/kernel/osrelease", b"6.12.0-ginux.0.1\n"),
    (b"sys/kernel/msgmni", b"32000\n"),
    // As many tasks as a domain may have processes (linux_process::
    // PROCESS_LIMIT): what tests size their forks by.
    (b"sys/kernel/threads-max", b"4096\n"),
    (b"sys/fs/inotify/max_queued_events", b"16384\n"),
    (b"sys/fs/inotify/max_user_instances", b"128\n"),
    (b"sys/fs/inotify/max_user_watches", b"65536\n"),
    // fanotify's queue length and per-user limits (linux_fanotify): the
    // user/ ones are each user namespace's, the fs/fanotify/ ones the
    // domain's initial namespace's (cpu/fanotify.rs computes both).
    (b"sys/fs/fanotify/max_queued_events", b"16384\n"),
    (b"sys/fs/fanotify/max_user_groups", b"128\n"),
    (b"sys/fs/fanotify/max_user_marks", b"8192\n"),
    (b"sys/user/max_fanotify_groups", b"128\n"),
    (b"sys/user/max_fanotify_marks", b"8192\n"),
    (b"sys/kernel/keys/root_maxkeys", b"1000000\n"),
    (b"sys/kernel/keys/root_maxbytes", b"25000000\n"),
    // The key quotas of users other than root (linux_key_limits).
    (b"sys/kernel/keys/maxkeys", b"200\n"),
    (b"sys/kernel/keys/maxbytes", b"20000\n"),
    // Seconds a revoked or expired key stays linked before the garbage
    // collector drops it (linux_with_keys).
    (b"sys/kernel/keys/gc_delay", b"300\n"),
    // Link restrictions in sticky, world-writable directories (off, as
    // Linux boots; distributions turn them on): linux_check_hardlink_source
    // and linux_check_follow_link.
    (b"sys/fs/protected_hardlinks", b"0\n"),
    (b"sys/fs/protected_symlinks", b"0\n"),
]);
pub(super) const LINUX_PROC_CPUINFO_NODE: u16 = 0xf800;
pub(super) const LINUX_FILE_PROC_CPUINFO: u16 = LINUX_FILE_MASK | LINUX_PROC_CPUINFO_NODE;
pub(super) const LINUX_PROC_MEMINFO_NODE: u16 = 0xf700;
pub(super) const LINUX_FILE_PROC_MEMINFO: u16 = LINUX_FILE_MASK | LINUX_PROC_MEMINFO_NODE;
pub(super) const LINUX_RESOLV_CONF_NODE: u16 = 0xf600;
pub(super) const LINUX_FILE_RESOLV_CONF: u16 = LINUX_FILE_MASK | LINUX_RESOLV_CONF_NODE;
pub(super) const LINUX_PROC_STAT_NODE: u16 = 0xd300;
pub(super) const LINUX_FILE_PROC_STAT: u16 = LINUX_FILE_MASK | LINUX_PROC_STAT_NODE;
pub(super) const LINUX_PROC_UPTIME_NODE: u16 = 0xf500;
pub(super) const LINUX_FILE_PROC_UPTIME: u16 = LINUX_FILE_MASK | LINUX_PROC_UPTIME_NODE;
pub(super) const LINUX_PROC_LOADAVG_NODE: u16 = 0xf400;
pub(super) const LINUX_FILE_PROC_LOADAVG: u16 = LINUX_FILE_MASK | LINUX_PROC_LOADAVG_NODE;
pub(super) const LINUX_PROC_FILESYSTEMS_NODE: u16 = 0xf300;
/// `/proc/swaps`: the domain's swap areas (`crate::linux_swap`).
pub(super) const LINUX_PROC_SWAPS_NODE: u16 = 0x9700;
pub(super) const LINUX_FILE_PROC_SWAPS: u16 = LINUX_FILE_MASK | LINUX_PROC_SWAPS_NODE;
pub(super) const LINUX_FILE_PROC_FILESYSTEMS: u16 = LINUX_FILE_MASK | LINUX_PROC_FILESYSTEMS_NODE;
/// /proc/modules: the loaded modules, none (everything Ginux has is built
/// in, as /lib/modules/RELEASE/modules.builtin lists it).
pub(super) const LINUX_PROC_MODULES_NODE: u16 = 0xba00;
pub(super) const LINUX_FILE_PROC_MODULES: u16 = LINUX_FILE_MASK | LINUX_PROC_MODULES_NODE;
/// The directories of /proc/sys, as paths under the root: one for each
/// directory the `LINUX_PROC_SYSCTLS` values lie in. Directory `index` is
/// node `LINUX_PROC_SYS_DIRECTORY_FIRST_NODE + (index << 8)`, a directory
/// kind of the /proc/PID role, and inode `LINUX_PROC_SYS_DIRECTORY_INODES +
/// index`.
pub(super) const LINUX_PROC_SYS_DIRECTORIES: [&[u8]; 16] = [
    b"proc/sys",
    b"proc/sys/fs",
    b"proc/sys/fs/fanotify",
    b"proc/sys/fs/inotify",
    b"proc/sys/fs/mqueue",
    b"proc/sys/kernel",
    b"proc/sys/kernel/keys",
    b"proc/sys/kernel/random",
    b"proc/sys/net",
    b"proc/sys/net/ipv4",
    b"proc/sys/net/ipv4/conf",
    b"proc/sys/net/ipv4/conf/all",
    b"proc/sys/net/ipv4/conf/default",
    b"proc/sys/net/ipv4/conf/lo",
    b"proc/sys/user",
    b"proc/sys/vm",
];
pub(super) const LINUX_PROC_SYS_DIRECTORY_FIRST_NODE: u16 = 0x7000;
/// The inodes of /proc's files and directories: fixed ones below 64, the
/// image's directories from 64 (a node each), and these ranges, so no two
/// share one.
pub(super) const LINUX_PROC_SYSCTL_INODES: u64 = 0x10_0000;
pub(super) const LINUX_PROC_SYS_DIRECTORY_INODES: u64 = 0x10_1000;
/// Files whose inode is their node's (`linux_proc_node_inode`).
pub(super) const LINUX_PROC_NODE_INODES: u64 = 0x10_2000;
/// /proc/keys and /proc/key-users: the domain's keys a reader may view,
/// and each user's key count and quota (ginux_keyrings).
pub(super) const LINUX_PROC_KEYS_NODE: u16 = 0x9e00;
pub(super) const LINUX_FILE_PROC_KEYS: u16 = LINUX_FILE_MASK | LINUX_PROC_KEYS_NODE;
pub(super) const LINUX_PROC_KEY_USERS_NODE: u16 = 0x9f00;
pub(super) const LINUX_FILE_PROC_KEY_USERS: u16 = LINUX_FILE_MASK | LINUX_PROC_KEY_USERS_NODE;
/// /proc/config.gz: Ginux's kernel configuration (`kernel_config`).
pub(super) const LINUX_PROC_CONFIG_NODE: u16 = 0xa900;
pub(super) const LINUX_FILE_PROC_CONFIG: u16 = LINUX_FILE_MASK | LINUX_PROC_CONFIG_NODE;

/// The kernel configuration as Linux's .config lists it: only what Ginux
/// implements for Linux programs, so a test that needs a missing feature
/// (CONFIG_BLK_DEV_LOOP, CONFIG_TIME_NS, ...) skips itself.
const LINUX_KERNEL_CONFIG: &[u8] = include_bytes!("kernel_config");
const LINUX_KERNEL_CONFIG_GZIP_SIZE: usize = 10 + 5 + LINUX_KERNEL_CONFIG.len() + 8;

/// `LINUX_KERNEL_CONFIG` as /proc/config.gz serves it: a gzip member
/// holding one stored (uncompressed) deflate block, built at compile time.
pub(super) const LINUX_PROC_CONFIG_GZ: [u8; LINUX_KERNEL_CONFIG_GZIP_SIZE] = {
    const fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0_u32;
        let mut index = 0;
        while index < bytes.len() {
            crc ^= bytes[index] as u32;
            let mut bit = 0;
            while bit < 8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
                bit += 1;
            }
            index += 1;
        }
        !crc
    }
    let data = LINUX_KERNEL_CONFIG;
    assert!(data.len() <= 0xffff);
    let mut output = [0_u8; LINUX_KERNEL_CONFIG_GZIP_SIZE];
    // Magic, deflate, no flags, no time, no extra flags, Unix.
    let header = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let mut index = 0;
    while index < header.len() {
        output[index] = header[index];
        index += 1;
    }
    // The final stored block: its length and the length's complement.
    let length = data.len() as u16;
    output[10] = 1;
    output[11] = length as u8;
    output[12] = (length >> 8) as u8;
    output[13] = !length as u8;
    output[14] = (!length >> 8) as u8;
    let mut offset = 0;
    while offset < data.len() {
        output[15 + offset] = data[offset];
        offset += 1;
    }
    let trailer_start = 15 + data.len();
    let crc = crc32(data).to_le_bytes();
    let size = (data.len() as u32).to_le_bytes();
    let mut byte = 0;
    while byte < 4 {
        output[trailer_start + byte] = crc[byte];
        output[trailer_start + 4 + byte] = size[byte];
        byte += 1;
    }
    output
};
pub(super) const LINUX_PROC_CMDLINE_NODE: u16 = 0xf200;
pub(super) const LINUX_FILE_PROC_CMDLINE: u16 = LINUX_FILE_MASK | LINUX_PROC_CMDLINE_NODE;
pub(super) const LINUX_PROC_PID1_STAT_NODE: u16 = 0xf100;
pub(super) const LINUX_FILE_PROC_PID1_STAT: u16 = LINUX_FILE_MASK | LINUX_PROC_PID1_STAT_NODE;
pub(super) const LINUX_PROC_PID1_STATM_NODE: u16 = 0xf000;
pub(super) const LINUX_FILE_PROC_PID1_STATM: u16 = LINUX_FILE_MASK | LINUX_PROC_PID1_STATM_NODE;
pub(super) const LINUX_PROC_PID2_STAT_NODE: u16 = 0xef00;
pub(super) const LINUX_FILE_PROC_PID2_STAT: u16 = LINUX_FILE_MASK | LINUX_PROC_PID2_STAT_NODE;
pub(super) const LINUX_PROC_PID2_STATM_NODE: u16 = 0xee00;
pub(super) const LINUX_FILE_PROC_PID2_STATM: u16 = LINUX_FILE_MASK | LINUX_PROC_PID2_STATM_NODE;
/// /proc/PID/coredump_filter: which memory core files hold. Ginux's hold
/// none (an ELF header and a process-information note), so it is 0.
pub(super) const LINUX_PROC_COREDUMP_FILTER_NODE: u16 = 0xae00;
pub(super) const LINUX_FILE_PROC_COREDUMP_FILTER: u16 =
    LINUX_FILE_MASK | LINUX_PROC_COREDUMP_FILTER_NODE;
pub(super) const LINUX_PROC_CGROUP_NODE: u16 = 0xec00;
pub(super) const LINUX_FILE_PROC_CGROUP: u16 = LINUX_FILE_MASK | LINUX_PROC_CGROUP_NODE;
pub(super) const LINUX_PROC_PROCESS_CMDLINE_NODE: u16 = 0xea00;
pub(super) const LINUX_FILE_PROC_PROCESS_CMDLINE: u16 =
    LINUX_FILE_MASK | LINUX_PROC_PROCESS_CMDLINE_NODE;
pub(super) const LINUX_PROC_PROCESS_ENVIRON_NODE: u16 = 0xe900;
pub(super) const LINUX_FILE_PROC_PROCESS_ENVIRON: u16 =
    LINUX_FILE_MASK | LINUX_PROC_PROCESS_ENVIRON_NODE;
pub(super) const LINUX_PROC_FILE_MAX_NODE: u16 = 0xe800;
pub(super) const LINUX_FILE_PROC_FILE_MAX: u16 = LINUX_FILE_MASK | LINUX_PROC_FILE_MAX_NODE;
pub(super) const LINUX_PROC_NR_OPEN_NODE: u16 = linux_proc_sysctl_node_named(b"sys/fs/nr_open");
/// `/proc/sys/net/ipv4/ping_group_range`, a two-number value.
pub(super) const LINUX_PING_GROUP_RANGE: &[u8] = b"sys/net/ipv4/ping_group_range";
/// The largest gid ping_group_range takes (Linux's GID_T_MAX).
pub(super) const LINUX_PING_GROUP_MAX: i64 = 0x7fff_ffff;
pub(super) const LINUX_FILE_PROC_NR_OPEN: u16 = LINUX_FILE_MASK | LINUX_PROC_NR_OPEN_NODE;
pub(super) const LINUX_PROC_OOM_SCORE_ADJ_NODE: u16 = 0xe600;
/// `/proc/PID/timens_offsets`: the offsets of the time namespace PID's
/// children are born into.
pub(super) const LINUX_PROC_TIMENS_OFFSETS_NODE: u16 = 0xbc00;
pub(super) const LINUX_FILE_PROC_TIMENS_OFFSETS: u16 =
    LINUX_FILE_MASK | LINUX_PROC_TIMENS_OFFSETS_NODE;
pub(super) const LINUX_FILE_PROC_OOM_SCORE_ADJ: u16 =
    LINUX_FILE_MASK | LINUX_PROC_OOM_SCORE_ADJ_NODE;
pub(super) const LINUX_PROC_USER_NAMESPACE_NODE: u16 = 0xe500;
pub(super) const LINUX_FILE_PROC_USER_NAMESPACE: u16 =
    LINUX_FILE_MASK | LINUX_PROC_USER_NAMESPACE_NODE;
pub(super) const LINUX_PROC_FDINFO_NODE: u16 = 0xe400;
pub(super) const LINUX_FILE_PROC_FDINFO: u16 = LINUX_FILE_MASK | LINUX_PROC_FDINFO_NODE;
pub(super) const LINUX_PROC_HOSTNAME_NODE: u16 = 0xe300;
pub(super) const LINUX_FILE_PROC_HOSTNAME: u16 = LINUX_FILE_MASK | LINUX_PROC_HOSTNAME_NODE;
pub(super) const LINUX_PROC_BOOT_ID_NODE: u16 = 0xdf00;
pub(super) const LINUX_FILE_PROC_BOOT_ID: u16 = LINUX_FILE_MASK | LINUX_PROC_BOOT_ID_NODE;
pub(super) const LINUX_PROC_DYNAMIC_STAT_NODE: u16 = 0xe200;
pub(super) const LINUX_FILE_PROC_DYNAMIC_STAT: u16 = LINUX_FILE_MASK | LINUX_PROC_DYNAMIC_STAT_NODE;
pub(super) const LINUX_PROC_DYNAMIC_STATUS_NODE: u16 = 0xe100;
pub(super) const LINUX_FILE_PROC_DYNAMIC_STATUS: u16 =
    LINUX_FILE_MASK | LINUX_PROC_DYNAMIC_STATUS_NODE;
pub(super) const LINUX_PROC_DYNAMIC_STATM_NODE: u16 = 0xe000;
pub(super) const LINUX_PROC_DYNAMIC_MAPS_NODE: u16 = 0xd100;
pub(super) const LINUX_FILE_PROC_DYNAMIC_MAPS: u16 = LINUX_FILE_MASK | LINUX_PROC_DYNAMIC_MAPS_NODE;
/// /proc/PID/pagemap: eight bytes per virtual page, bit 63 set when the
/// page is present.
pub(super) const LINUX_PROC_DYNAMIC_PAGEMAP_NODE: u16 = 0xa700;
pub(super) const LINUX_FILE_PROC_DYNAMIC_PAGEMAP: u16 =
    LINUX_FILE_MASK | LINUX_PROC_DYNAMIC_PAGEMAP_NODE;
/// /proc/PID/mem: the process's memory, at file offset = virtual address.
pub(super) const LINUX_PROC_DYNAMIC_MEM_NODE: u16 = 0xbb00;
pub(super) const LINUX_FILE_PROC_DYNAMIC_MEM: u16 = LINUX_FILE_MASK | LINUX_PROC_DYNAMIC_MEM_NODE;
/// /proc/PID/smaps: maps with each area's sizes (Rss, Locked, ...).
pub(super) const LINUX_PROC_DYNAMIC_SMAPS_NODE: u16 = 0xaf00;
pub(super) const LINUX_FILE_PROC_DYNAMIC_SMAPS: u16 =
    LINUX_FILE_MASK | LINUX_PROC_DYNAMIC_SMAPS_NODE;
pub(super) const LINUX_FILE_PROC_DYNAMIC_STATM: u16 =
    LINUX_FILE_MASK | LINUX_PROC_DYNAMIC_STATM_NODE;
/// /proc/PID/io: the process's I/O counts (`linux_process::IoAccounting`).
pub(super) const LINUX_PROC_DYNAMIC_IO_NODE: u16 = 0xc500;
pub(super) const LINUX_FILE_PROC_DYNAMIC_IO: u16 = LINUX_FILE_MASK | LINUX_PROC_DYNAMIC_IO_NODE;
pub(super) const LINUX_CGROUP_DIRECTORY_NODE: u16 = 0xeb00;
pub(super) const LINUX_CGROUP_DIRECTORY: u16 =
    LINUX_DEVICE_DIRECTORY | LINUX_FILE_PROC_STATUS | LINUX_CGROUP_DIRECTORY_NODE;
pub(super) const LINUX_ROOT_NODE_SHIFT: u32 = 8;
pub(super) const LINUX_ROOT_NODE_MASK: u16 = 0xff00;
pub(super) const LINUX_MOUNTINFO_FILE_NODE: u16 = 0xfe00;
pub(super) const LINUX_FILE_PROC_MOUNTINFO: u16 = LINUX_FILE_MASK | LINUX_MOUNTINFO_FILE_NODE;
pub(super) const LINUX_UID_MAP_FILE_NODE: u16 = 0xfd00;
pub(super) const LINUX_FILE_PROC_UID_MAP: u16 = LINUX_FILE_MASK | LINUX_UID_MAP_FILE_NODE;
pub(super) const LINUX_GID_MAP_FILE_NODE: u16 = 0xfc00;
pub(super) const LINUX_FILE_PROC_GID_MAP: u16 = LINUX_FILE_MASK | LINUX_GID_MAP_FILE_NODE;
pub(super) const LINUX_SETGROUPS_FILE_NODE: u16 = 0xfb00;
pub(super) const LINUX_FILE_PROC_SETGROUPS: u16 = LINUX_FILE_MASK | LINUX_SETGROUPS_FILE_NODE;
pub(super) const LINUX_TMP_FILE_NODE: u16 = 0xff00;
pub(super) const LINUX_FILE_TMP_SCRATCH: u16 = LINUX_FILE_MASK | LINUX_TMP_FILE_NODE;
pub(super) const LINUX_FRAMEBUFFER_NODE: u16 = 0xde00;
pub(super) const LINUX_FILE_FRAMEBUFFER: u16 = LINUX_FILE_MASK | LINUX_FRAMEBUFFER_NODE;
/// /dev/input/eventN uses node LINUX_INPUT_NODE_FIRST + N for N below
/// linux_input::DEVICE_LIMIT.
pub(super) const LINUX_INPUT_NODE_FIRST: u16 = 0xd800;
/// The fixed `/proc/1/status`: init, with root's capability sets
/// (every capability permitted, effective and in the bounding set).
pub(super) const LINUX_PROC_PID1_STATUS: &[u8] =
    b"Name:\tinit\nState:\tR (running)\nPid:\t1\nPPid:\t0\n\
CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\n\
CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
const _: () = assert!(ginux_credentials::capability::ALL == 0x1ff_ffff_ffff);
pub(super) const LINUX_PROC_PID2_RUNNING_STATUS: &[u8] =
    b"Name:\tinit\nState:\tR (running)\nPid:\t2\nPPid:\t1\n";
pub(super) const LINUX_PROC_PID2_STOPPED_STATUS: &[u8] =
    b"Name:\tinit\nState:\tT (stopped)\nPid:\t2\nPPid:\t1\n";
pub(super) const LINUX_PROC_PID2_ZOMBIE_STATUS: &[u8] =
    b"Name:\tinit\nState:\tZ (zombie)\nPid:\t2\nPPid:\t1\n";
pub(super) const LINUX_PROC_CPUINFO: &[u8] = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: Ginux virtual x86-64 CPU\nstepping\t: 10\ncpu MHz\t\t: 1000.000\ncache size\t: 16384 KB\nphysical id\t: 0\nsiblings\t: 1\ncore id\t\t: 0\ncpu cores\t: 1\nfpu\t\t: yes\ncpuid level\t: 13\nflags\t\t: fpu tsc msr pae cx8 apic sep mtrr pge cmov pat clflush mmx fxsr sse sse2 syscall nx lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq pni ssse3 cx16 sse4_1 sse4_2 x2apic popcnt aes xsave avx rdrand hypervisor\nbogomips\t: 2000.00\nclflush size\t: 64\ncache_alignment\t: 64\naddress sizes\t: 46 bits physical, 48 bits virtual\n\n";
pub(super) const LINUX_PROC_STAT: &[u8] = b"cpu  1 0 1 100 0 0 0 0 0 0\ncpu0 1 0 1 100 0 0 0 0 0 0\nintr 0\nctxt 1\nbtime 0\nprocesses 1\nprocs_running 1\nprocs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n";
pub(super) const LINUX_PROC_LOADAVG: &[u8] = b"0.00 0.00 0.00 1/1 1\n";
pub(super) const LINUX_PROC_FILESYSTEMS: &[u8] =
    b"nodev\tproc\nnodev\ttmpfs\nnodev\tramfs\nnodev\tdevtmpfs\n\text2\n\text3\n\text4\nnodev\toverlay\n";
pub(super) const LINUX_PROC_CMDLINE: &[u8] = b"ginux immutable=1\n";
pub(super) const LINUX_PROC_CGROUP: &[u8] = b"0::/\n";
pub(super) const LINUX_PROC_PROCESS_CMDLINE: &[u8] = b"/sbin/init\0";
pub(super) const LINUX_PROC_PROCESS_ENVIRON: &[u8] = b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0PWD=/\0TERM=linux\0container=ginux\0SYSTEMD_GETTY_AUTO=1\0";
pub(super) const LINUX_PROC_FILE_MAX: &[u8] = b"9223372036854775807\n";
pub(super) const LINUX_PROC_NR_OPEN: &[u8] = b"1048576\n";
pub(super) const LINUX_PROC_PID1_STAT: &[u8] = b"1 (init) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1 1048576 256 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
pub(super) const LINUX_PROC_PID1_STATM: &[u8] = b"256 64 32 16 0 32 0\n";
pub(super) const LINUX_PROC_PID2_RUNNING_STAT: &[u8] = b"2 (init) R 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1 1048576 256 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
pub(super) const LINUX_PROC_PID2_STOPPED_STAT: &[u8] = b"2 (init) T 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1 1048576 256 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
pub(super) const LINUX_PROC_PID2_ZOMBIE_STAT: &[u8] = b"2 (init) Z 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
pub(super) const LINUX_PROC_PID2_STATM: &[u8] = b"256 64 32 16 0 32 0\n";
pub(crate) const LINUX_EXEC_MAPPING_LIMIT: usize = 8;
pub(crate) const LINUX_ACTIVE_IMAGE_MAPPING_LIMIT: usize = 640;
pub(super) const LINUX_EXEC_VECTOR_LIMIT: usize = 32;
pub(super) const LINUX_EXEC_STACK_SIZE: usize = PAGE_SIZE / 2;
/// Pages for the runtime exec argument, environment and auxiliary-vector
/// image. Linux allows more, but this covers compiler and linker command lines.
pub(super) const LINUX_EXEC_ARGUMENT_PAGES: usize = 32;
/// The most argv or envp entries a runtime exec accepts.
pub(super) const LINUX_EXEC_ARGUMENT_LIMIT: usize = 8192;
/// Programs load low only if they end below the runtime heap.
pub(super) const LINUX_EXEC_LOW_LIMIT: u64 = 0x80_0000;
/// Where position-independent programs too large for the low window load:
/// the third 512 GiB slot of the address space, which mmap does not reach.
pub(super) const LINUX_EXEC_HIGH_LOAD_BASE: u64 = 0x100_0000_0000;
pub(super) const LINUX_EXEC_HIGH_LIMIT: u64 = 0x180_0000_0000;
/// The most pages a runtime exec copies in for its program and loader
/// segments (1 GiB: large Rust programs such as a Bevy application are
/// several hundred MiB). Exec copies the file; mapping its segments from a
/// page cache instead would lift the copy and the limit.
pub(super) const LINUX_EXEC_IMAGE_PAGE_LIMIT: usize = 262_144;
pub(super) const LINUX_PLATFORM: &[u8] = b"x86_64\0";
pub(super) const LINUX_F_DUPFD: u64 = 0;
pub(super) const LINUX_F_GETFD: u64 = 1;
pub(super) const LINUX_F_SETFD: u64 = 2;
pub(super) const LINUX_F_GETFL: u64 = 3;
pub(super) const LINUX_F_SETFL: u64 = 4;
pub(super) const LINUX_F_GETLK: u64 = 5;
pub(super) const LINUX_F_SETLK: u64 = 6;
pub(super) const LINUX_F_SETLKW: u64 = 7;
pub(super) const LINUX_F_OFD_GETLK: u64 = 36;
pub(super) const LINUX_F_OFD_SETLK: u64 = 37;
pub(super) const LINUX_F_OFD_SETLKW: u64 = 38;
pub(super) const LINUX_F_DUPFD_CLOEXEC: u64 = 1030;
pub(super) const LINUX_F_SETLEASE: u64 = 1024;
pub(super) const LINUX_F_GETLEASE: u64 = 1025;
pub(super) const LINUX_F_NOTIFY: u64 = 1026;
pub(super) const LINUX_F_SETSIG: u64 = 10;
pub(super) const LINUX_F_GETSIG: u64 = 11;
pub(super) const LINUX_F_CREATED_QUERY: u64 = 1028;
pub(super) const LINUX_F_ADD_SEALS: u64 = 1033;
pub(super) const LINUX_F_GET_SEALS: u64 = 1034;
pub(super) const LINUX_F_SEAL_SEAL: u32 = 0x0001;
pub(super) const LINUX_F_SEAL_SHRINK: u32 = 0x0002;
pub(super) const LINUX_F_SEAL_GROW: u32 = 0x0004;
pub(super) const LINUX_F_SEAL_WRITE: u32 = 0x0008;
pub(super) const LINUX_F_SEAL_FUTURE_WRITE: u32 = 0x0010;
pub(super) const LINUX_F_SEAL_EXEC: u32 = 0x0020;
pub(super) const LINUX_F_SEAL_MASK: u32 = LINUX_F_SEAL_SEAL
    | LINUX_F_SEAL_SHRINK
    | LINUX_F_SEAL_GROW
    | LINUX_F_SEAL_WRITE
    | LINUX_F_SEAL_FUTURE_WRITE
    | LINUX_F_SEAL_EXEC;
pub(super) const LINUX_FD_CLOEXEC: u8 = 1;
pub(super) const LINUX_CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;
pub(super) const LINUX_CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
pub(super) const LINUX_O_CLOEXEC: u64 = 0x80000;
pub(super) const LINUX_O_NOCTTY: u64 = 0x100;
pub(super) const LINUX_O_DIRECTORY: u64 = 0x10000;
/// O_DIRECT; on a pipe from pipe2(2), packet mode.
pub(super) const LINUX_O_DIRECT: u64 = 0x4000;
pub(super) const LINUX_O_CREAT: u64 = 0x40;
pub(super) const LINUX_O_EXCL: u64 = 0x80;
pub(super) const LINUX_O_TRUNC: u64 = 0x200;
pub(super) const LINUX_O_APPEND: u64 = 0x400;
pub(super) const LINUX_O_NONBLOCK: u64 = 0x800;
pub(super) const LINUX_O_ACCMODE: u64 = 3;
pub(super) const LINUX_PRIVATE_SECRET_DESCRIPTOR: u32 = 1 << 31;
pub(super) const LINUX_PRIVATE_IO_URING_DESCRIPTOR: u32 = 1 << 29;
/// An O_PATH | O_NOFOLLOW descriptor of a /proc fd entry: it names the
/// entry (a magic link) rather than the file the entry leads to.
pub(super) const LINUX_PRIVATE_PROC_LINK_DESCRIPTOR: u32 = 1 << 28;
/// A descriptor fanotify opened for a listener (FMODE_NONOTIFY): what is
/// done through it raises no inotify or fanotify events.
pub(super) const LINUX_PRIVATE_NONOTIFY_DESCRIPTOR: u32 = 1 << 30;
pub(super) const LINUX_O_LARGEFILE: u64 = 0x8000;
pub(super) const LINUX_O_NOFOLLOW: u64 = 0x20000;
pub(super) const LINUX_O_NOATIME: u64 = 0x40000;
pub(super) const LINUX_O_PATH: u64 = 0x20_0000;
pub(super) const LINUX_PR_SET_DUMPABLE: u64 = 4;
pub(super) const LINUX_PR_GET_DUMPABLE: u64 = 3;
pub(super) const LINUX_PR_SET_PDEATHSIG: u64 = 1;
pub(super) const LINUX_PR_GET_PDEATHSIG: u64 = 2;
pub(super) const LINUX_PR_GET_TIMING: u64 = 13;
pub(super) const LINUX_PR_SET_TIMING: u64 = 14;
pub(super) const LINUX_PR_SET_NAME: u64 = 15;
pub(super) const LINUX_PR_GET_NAME: u64 = 16;
pub(super) const LINUX_PR_GET_SECCOMP: u64 = 21;
pub(super) const LINUX_PR_SET_SECCOMP: u64 = 22;
pub(super) const LINUX_PR_CAPBSET_READ: u64 = 23;
pub(super) const LINUX_PR_CAPBSET_DROP: u64 = 24;
pub(super) const LINUX_PR_GET_SECUREBITS: u64 = 27;
pub(super) const LINUX_PR_SET_SECUREBITS: u64 = 28;
pub(super) const LINUX_PR_SET_NO_NEW_PRIVS: u64 = 38;
pub(super) const LINUX_PR_GET_NO_NEW_PRIVS: u64 = 39;
pub(super) const LINUX_PR_GET_TSC: u64 = 25;
pub(super) const LINUX_PR_SET_TSC: u64 = 26;
pub(super) const LINUX_PR_TSC_ENABLE: u64 = 1;
pub(super) const LINUX_PR_TSC_SIGSEGV: u64 = 2;
pub(super) const LINUX_PR_SET_TIMERSLACK: u64 = 29;
pub(super) const LINUX_PR_GET_TIMERSLACK: u64 = 30;
pub(super) const LINUX_PR_SET_CHILD_SUBREAPER: u64 = 36;
pub(super) const LINUX_PR_GET_CHILD_SUBREAPER: u64 = 37;
pub(super) const LINUX_PR_CAP_AMBIENT: u64 = 47;
pub(super) const LINUX_PR_TASK_PERF_EVENTS_DISABLE: u64 = 31;
pub(super) const LINUX_PR_TASK_PERF_EVENTS_ENABLE: u64 = 32;
/// SECBIT_NO_CAP_AMBIENT_RAISE: PR_CAP_AMBIENT_RAISE is refused.
pub(super) const LINUX_SECBIT_NO_CAP_AMBIENT_RAISE: u32 = 1 << 6;
pub(super) const LINUX_SECUREBITS_VALID_MASK: u32 = 0xff;
pub(super) const LINUX_PR_TIMING_STATISTICAL: u64 = 0;
pub(super) const LINUX_PERSONALITY_QUERY: u32 = u32::MAX;
pub(super) const LINUX_PERSONALITY_UNAME26: u32 = 0x0002_0000;
pub(super) const LINUX_PROCESS_NAME_SIZE: usize = 16;
pub(super) const LINUX_INITIAL_PROCESS_NAME: u64 = 0x7469_6e69;
pub(super) const LINUX_SIG_BLOCK: u64 = 0;
pub(super) const LINUX_SIG_UNBLOCK: u64 = 1;
pub(super) const LINUX_SIG_SETMASK: u64 = 2;
pub(super) const LINUX_SIGNAL_SET_SIZE: u64 = 8;
pub(super) const LINUX_SIGNAL_ACTION_SIZE: usize = 32;
pub(super) const LINUX_SIGNAL_COUNT: usize = 64;
pub(super) const LINUX_ALT_STACK_SIZE: usize = 24;
pub(super) const LINUX_MIN_ALT_STACK_SIZE: u64 = 2048;
pub(super) const LINUX_SS_DISABLE: u32 = 2;
pub(super) const LINUX_SS_AUTODISARM: u32 = 1 << 31;
pub(super) const LINUX_UNBLOCKABLE_SIGNALS: u64 = (1 << (9 - 1)) | (1 << (19 - 1));
pub(super) const LINUX_SIGSEGV: u64 = 11;
pub(super) const LINUX_SIGSYS: u64 = 31;
pub(super) const LINUX_SIGPIPE: u64 = 13;
pub(super) const LINUX_SIGALRM: u64 = 14;
pub(super) const LINUX_SIGTERM: u64 = 15;
pub(super) const LINUX_SIGCONT: u64 = 18;
pub(super) const LINUX_SIGXFSZ: u64 = 25;
pub(super) const LINUX_SI_USER: i32 = 0;
pub(super) const LINUX_SI_QUEUE: i32 = -1;
/// si_code of a POSIX timer's signal.
pub(super) const LINUX_SI_TIMER: i32 = -2;
pub(super) const LINUX_SI_TKILL: i32 = -6;
pub(super) const LINUX_SI_KERNEL: i32 = 0x80;
pub(super) const LINUX_SEGV_MAPERR: i32 = 1;
pub(super) const LINUX_SEGV_ACCERR: i32 = 2;
/// SIGBUS's si_code for an access past the end of a mapped file.
pub(super) const LINUX_BUS_ADRERR: i32 = 2;
pub(super) const LINUX_SA_NOCLDSTOP: u64 = 0x0000_0001;
pub(super) const LINUX_SA_NOCLDWAIT: u64 = 0x0000_0002;
pub(super) const LINUX_SA_SIGINFO: u64 = 0x0000_0004;
pub(super) const LINUX_SA_RESTART: u64 = 0x1000_0000;
pub(super) const LINUX_SA_RESTORER: u64 = 0x0400_0000;
pub(super) const LINUX_SA_ONSTACK: u64 = 0x0800_0000;
pub(super) const LINUX_SA_NODEFER: u64 = 0x4000_0000;
pub(super) const LINUX_SA_RESETHAND: u64 = 0x8000_0000;
/// The sigaction flags Linux keeps (UAPI_SA_FLAGS on x86-64): SA_NOCLDSTOP,
/// SA_NOCLDWAIT, SA_SIGINFO, SA_EXPOSE_TAGBITS, SA_RESTORER, SA_ONSTACK,
/// SA_RESTART, SA_NODEFER and SA_RESETHAND; others are cleared.
pub(super) const LINUX_UAPI_SA_FLAGS: u64 =
    0x1 | 0x2 | 0x4 | 0x800 | 0x0400_0000 | 0x0800_0000 | 0x1000_0000 | 0x4000_0000 | 0x8000_0000;
pub(super) const LINUX_SIGNAL_FRAME_SIZE: usize = 440;
pub(super) const LINUX_SIGNAL_FRAME_INFO_OFFSET: u64 = 312;
pub(super) const LINUX_SIGNAL_FRAME_CONTEXT_OFFSET: u64 = 8;
pub(super) const LINUX_SIGNAL_RED_ZONE_SIZE: u64 = 128;
pub(super) const LINUX_UC_SIGCONTEXT_SS: u64 = 0x2;
pub(super) const LINUX_UC_STRICT_RESTORE_SS: u64 = 0x4;
pub(super) const LINUX_SIGNAL_RESTORABLE_RFLAGS: u64 = 0x0005_0dd5;
pub(super) const LINUX_SS_ONSTACK: u32 = 1;
pub(super) const LINUX_UTSNAME_SIZE: usize = 6 * 65;
pub(super) const LINUX_ROBUST_LIST_HEAD_SIZE: usize = 24;
pub(super) const LINUX_CLEAR_CHILD_TID_OFFSET: u64 = 400;
pub(super) const LINUX_ROBUST_LIST_OFFSET: u64 = 432;
pub(super) const LINUX_CLOCK_MONOTONIC: u64 = 1;
pub(super) const LINUX_CLOCK_REALTIME: u64 = 0;
pub(super) const LINUX_CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
pub(super) const LINUX_CLOCK_THREAD_CPUTIME_ID: u64 = 3;
pub(super) const LINUX_CLOCK_MONOTONIC_RAW: u64 = 4;
pub(super) const LINUX_CLOCK_REALTIME_COARSE: u64 = 5;
pub(super) const LINUX_CLOCK_MONOTONIC_COARSE: u64 = 6;
pub(super) const LINUX_CLOCK_BOOTTIME: u64 = 7;
pub(super) const LINUX_CLOCK_REALTIME_ALARM: u64 = 8;
pub(super) const LINUX_CLOCK_BOOTTIME_ALARM: u64 = 9;
pub(super) const LINUX_CLOCK_TAI: u64 = 11;
pub(super) const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;
pub(super) const MICROSECONDS_PER_SECOND: u64 = 1_000_000;
pub(super) const LINUX_CLOCK_TICKS_PER_SECOND: u64 = 100;
// The verification workload issues additional yield hints while no peer is
// runnable. Only the fifteen calls that transfer execution are switches.
pub(super) const LINUX_VERIFICATION_YIELD_SWITCHES: u32 = 15;
use super::PAGE_SIZE;

/// The fixed file nodes and the `/proc/sys` nodes are distinct and clear of
/// the `/dev/input/eventN` range, so no file is taken for another.
const _: () = {
    const NODES: [u16; 54] = [
        LINUX_PROC_TASK_DIRECTORY_NODE,
        LINUX_PROC_TASK_COMM_NODE,
        LINUX_PROC_TASK_STAT_NODE,
        LINUX_PROC_SYSVIPC_MSG_NODE,
        LINUX_PROC_SYSVIPC_SHM_NODE,
        LINUX_PROC_SYSVIPC_SEM_NODE,
        LINUX_PROC_PID2_DIRECTORY_NODE,
        LINUX_PROC_FD_DIRECTORY_NODE,
        LINUX_PROC_PID2_STATUS_NODE,
        LINUX_PROC_MOUNTS_NODE,
        LINUX_PROC_CPUINFO_NODE,
        LINUX_PROC_MEMINFO_NODE,
        LINUX_RESOLV_CONF_NODE,
        LINUX_PROC_STAT_NODE,
        LINUX_PROC_UPTIME_NODE,
        LINUX_PROC_LOADAVG_NODE,
        LINUX_PROC_FILESYSTEMS_NODE,
        LINUX_PROC_SWAPS_NODE,
        LINUX_PROC_MODULES_NODE,
        LINUX_PROC_KEYS_NODE,
        LINUX_PROC_KEY_USERS_NODE,
        LINUX_PROC_CONFIG_NODE,
        LINUX_PROC_COREDUMP_FILTER_NODE,
        LINUX_PROC_CMDLINE_NODE,
        LINUX_PROC_PID1_STAT_NODE,
        LINUX_PROC_PID1_STATM_NODE,
        LINUX_PROC_PID2_STAT_NODE,
        LINUX_PROC_PID2_STATM_NODE,
        LINUX_PROC_CGROUP_NODE,
        LINUX_PROC_PROCESS_CMDLINE_NODE,
        LINUX_PROC_PROCESS_ENVIRON_NODE,
        LINUX_PROC_FILE_MAX_NODE,
        LINUX_PROC_OOM_SCORE_ADJ_NODE,
        LINUX_PROC_TIMENS_OFFSETS_NODE,
        LINUX_PROC_USER_NAMESPACE_NODE,
        LINUX_PROC_FDINFO_NODE,
        LINUX_PROC_HOSTNAME_NODE,
        LINUX_PROC_BOOT_ID_NODE,
        LINUX_PROC_DYNAMIC_STAT_NODE,
        LINUX_PROC_DYNAMIC_STATUS_NODE,
        LINUX_PROC_DYNAMIC_STATM_NODE,
        LINUX_PROC_DYNAMIC_IO_NODE,
        LINUX_PROC_DYNAMIC_MAPS_NODE,
        LINUX_PROC_DYNAMIC_SMAPS_NODE,
        LINUX_PROC_DYNAMIC_PAGEMAP_NODE,
        LINUX_PROC_DYNAMIC_MEM_NODE,
        LINUX_CGROUP_DIRECTORY_NODE,
        LINUX_MOUNTINFO_FILE_NODE,
        LINUX_UID_MAP_FILE_NODE,
        LINUX_GID_MAP_FILE_NODE,
        LINUX_SETGROUPS_FILE_NODE,
        LINUX_TMP_FILE_NODE,
        LINUX_FRAMEBUFFER_NODE,
        LINUX_PROC_SYSRQ_TRIGGER_NODE,
    ];
    const fn node(index: usize) -> u16 {
        if index < NODES.len() {
            NODES[index]
        } else {
            LINUX_PROC_SYSCTLS[index - NODES.len()].0
        }
    }
    let input_end = LINUX_INPUT_NODE_FIRST + ((crate::linux_input::DEVICE_LIMIT as u16) << 8);
    // The /proc/sys values' nodes come first, then the directories', then
    // every other node (from 0x9800).
    assert!(
        LINUX_PROC_SYSCTL_FIRST_NODE as usize + (LINUX_PROC_SYSCTLS.len() << 8)
            <= LINUX_PROC_SYS_DIRECTORY_FIRST_NODE as usize
    );
    assert!(
        LINUX_PROC_SYS_DIRECTORY_FIRST_NODE as usize + (LINUX_PROC_SYS_DIRECTORIES.len() << 8)
            <= 0x9800
    );
    // Every /proc/sys value's directory is listed.
    let mut value = 0;
    while value < LINUX_PROC_SYSCTLS.len() {
        let path = LINUX_PROC_SYSCTLS[value].1;
        let mut end = path.len();
        while end > 0 && path[end - 1] != b'/' {
            end -= 1;
        }
        let mut directory = 0;
        while directory < LINUX_PROC_SYS_DIRECTORIES.len()
            && !is_proc_directory_of(LINUX_PROC_SYS_DIRECTORIES[directory], path, end - 1)
        {
            directory += 1;
        }
        assert!(directory < LINUX_PROC_SYS_DIRECTORIES.len());
        value += 1;
    }
    let total = NODES.len() + LINUX_PROC_SYSCTLS.len();
    let mut index = 0;
    while index < total {
        assert!(node(index) < LINUX_INPUT_NODE_FIRST || node(index) >= input_end);
        let mut other = index + 1;
        while other < total {
            assert!(node(index) != node(other));
            other += 1;
        }
        index += 1;
    }
};

/// Whether `directory` ("proc/" and a path) is `/proc/` + `path[..length]`.
const fn is_proc_directory_of(directory: &[u8], path: &[u8], length: usize) -> bool {
    if directory.len() != 5 + length {
        return false;
    }
    let mut index = 0;
    while index < length {
        if directory[5 + index] != path[index] {
            return false;
        }
        index += 1;
    }
    true
}
