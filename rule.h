#include <seccomp.h>
#include <fcntl.h>
#include <stdbool.h>

#define LOAD_SECCOMP_FAILED 1

int c_cpp_rules(char *target, bool allow_write_file)
{
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx)
    {
        return LOAD_SECCOMP_FAILED;
    }
    // for execve
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)target)) != 0)
    {
        return LOAD_SECCOMP_FAILED;
    }

    int syscalls_whitelist[] = {SCMP_SYS(read), SCMP_SYS(fstat),
                                SCMP_SYS(mmap), SCMP_SYS(mprotect),
                                SCMP_SYS(munmap), SCMP_SYS(uname),
                                SCMP_SYS(arch_prctl), SCMP_SYS(brk),
                                SCMP_SYS(access), SCMP_SYS(exit_group),
                                SCMP_SYS(close), SCMP_SYS(readlink),
                                SCMP_SYS(sysinfo), SCMP_SYS(write),
                                SCMP_SYS(writev), SCMP_SYS(lseek),
                                SCMP_SYS(clock_gettime), SCMP_SYS(fcntl),
                                SCMP_SYS(pread64), SCMP_SYS(faccessat),
                                SCMP_SYS(newfstatat), SCMP_SYS(set_tid_address),
                                SCMP_SYS(set_robust_list), SCMP_SYS(rseq),
                                SCMP_SYS(prlimit64), SCMP_SYS(ioctl),
                                SCMP_SYS(futex),
                                SCMP_SYS(getrandom)};

    // add rules
    int syscalls_whitelist_length = sizeof(syscalls_whitelist) / sizeof(int);
    for (int i = 0; i < syscalls_whitelist_length; i++)
    {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls_whitelist[i], 0) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
    }

    // file write permission
    if (!allow_write_file)
    {
        // do not allow "w" and "rw"
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0)) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0)) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
    }
    else
    {
        // allow "w" and "rw"
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
    }

    if (seccomp_load(ctx) != 0)
    {
        return LOAD_SECCOMP_FAILED;
    }
    seccomp_release(ctx);
    return 0;
}

int python3_rules(char *target)
{

    return 0;
}

int general_rules(char *target, bool allow_write_file)
{
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx)
    {
        return LOAD_SECCOMP_FAILED;
    }

    // for execve
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_NE, (scmp_datum_t)target)) != 0)
    {
        return LOAD_SECCOMP_FAILED;
    }

    int syscalls_blacklist[] = {SCMP_SYS(clone),
                                SCMP_SYS(fork), SCMP_SYS(vfork),
                                SCMP_SYS(kill)};
    int syscalls_blacklist_length = sizeof(syscalls_blacklist) / sizeof(int);

    for (int i = 0; i < syscalls_blacklist_length; i++)
    {
        if (seccomp_rule_add(ctx, SCMP_ACT_KILL, syscalls_blacklist[i], 0) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
    }

    if (!allow_write_file)
    {
        // do not allow "w" and "rw" using open
        if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
        // do not allow "w" and "rw" using openat
        if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) != 0)
        {
            return LOAD_SECCOMP_FAILED;
        }
    }

    if (seccomp_load(ctx) != 0)
    {
        return LOAD_SECCOMP_FAILED;
    }
    seccomp_release(ctx);
    return 0;
}
