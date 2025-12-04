#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "lang.h"
#include "rule.h"

const pid_t SANDBOX_UID = 1450;
const pid_t SANDBOX_GID = 1450;

pid_t pid;
long time_limit_to_watch;
bool time_limit_exceeded_killed;

void *watcher_thread(void *arg)
{
    usleep(time_limit_to_watch * 1000);
    time_limit_exceeded_killed = true;
    kill(pid, SIGKILL);
    return arg; // Avoid 'parameter set but not used' warning
}

int main(int argc, char **argv)
{
    if (argc != 12 + 1)
    {
        fprintf(stderr, "Error: need 12 arguments\n");
        fprintf(stderr, "Usage: %s lang_id compile file_stdin file_stdout file_stderr time_limit memory_limit large_stack output_limit process_limit allow_network_access file_result\n", argv[0]);
        return 1;
    }

    if (getuid() != 0)
    {
        fprintf(stderr, "Error: need root privileges\n");
        return 1;
    }

    char *file_stdin = argv[3],
         *file_stdout = argv[4],
         *file_stderr = argv[5],
         *file_result = argv[12];
    long lang_id = strtol(argv[1], NULL, 10),
         compile = strtol(argv[2], NULL, 10),
         time_limit = strtol(argv[6], NULL, 10),
         memory_limit = strtol(argv[7], NULL, 10),
         large_stack = strtol(argv[8], NULL, 10),
         output_limit = strtol(argv[9], NULL, 10),
         process_limit = strtol(argv[10], NULL, 10),
         allow_network_access = strtol(argv[11], NULL, 10);

    time_limit_to_watch = time_limit + 300;

    char *program = 0;
    char **program_argv = 0;
    int allow_write_file = 0;

    char *env_allow = getenv("SANDBOX_ALLOW_WRITE");
    if (env_allow && strlen(env_allow))
        allow_write_file = atoi(env_allow) != 0;

    if (lang_id == 0)
    { // c11
        if (compile)
        {
            program = c_compile_argv[0];
            program_argv = c_compile_argv;
        }
        else
        {
            program = c_execution[0];
            program_argv = c_execution;
        }
    }
    else if (lang_id == 1)
    { // cpp11
        if (compile)
        {
            program = cpp_compile_argv[0];
            program_argv = cpp_compile_argv;
        }
        else
        {
            program = cpp_execution[0];
            program_argv = cpp_execution;
        }
    }
    else if (lang_id == 2)
    { // python3
        program = python3_execution[0];
        program_argv = python3_execution;
    }

#ifdef LOG
    printf("Program: %s\n", program);
    printf("Standard input file: %s\n", file_stdin);
    printf("Standard output file: %s\n", file_stdout);
    printf("Standard error file: %s\n", file_stderr);
    printf("Time limit (seconds): %lu\n", time_limit);
    printf("Memory limit (kilobytes): %lu\n", memory_limit);
    printf("Output limit (bytes): %lu\n", output_limit);
    printf("Process limit: %lu\n", process_limit);
    printf("Result file: %s\n", file_result);
#endif

    pid = fork();
    if (pid > 0)
    {
        // Parent process

        FILE *fresult = fopen(file_result, "w");
        if (!fresult)
        {
            printf("Failed to open result file '%s'.", file_result);
            return -1;
        }

        if (time_limit)
        {
            pthread_t thread_id;
            pthread_create(&thread_id, NULL, &watcher_thread, NULL);
        }

        struct rusage usage;
        int status;
        if (wait4(pid, &status, 0, &usage) == -1)
        {
            fprintf(fresult, "RE\nwait4() = -1\n0\n0\n");
            return 0;
        }

        if (WIFEXITED(status))
        {
            // Not signaled - maybe exited normally
            if (time_limit_exceeded_killed || (usage.ru_utime.tv_sec * 1000 + usage.ru_utime.tv_usec / 1000) > time_limit)
            {
                fprintf(fresult, "TLE\nWEXITSTATUS() = %d\n", WEXITSTATUS(status));
            }
            else if (usage.ru_maxrss > memory_limit)
            {
                fprintf(fresult, "MLE\nWEXITSTATUS() = %d\n", WEXITSTATUS(status));
            }
            else if (WEXITSTATUS(status) != 0)
            {
                fprintf(fresult, "RE\nWIFEXITED - WEXITSTATUS() = %d\n", WEXITSTATUS(status));
            }
            else
            {
                fprintf(fresult, "Exited Normally\nWIFEXITED - WEXITSTATUS() = %d\n", WEXITSTATUS(status));
            }
        }
        else
        {
            // Signaled
            int sig = WTERMSIG(status);
            if (time_limit_exceeded_killed || (usage.ru_utime.tv_sec * 1000 + usage.ru_utime.tv_usec / 1000) > time_limit || sig == SIGXCPU)
            {
                fprintf(fresult, "TLE\nWEXITSTATUS() = %d, WTERMSIG() = %d (%s)\n", WEXITSTATUS(status), sig, strsignal(sig));
            }
            else if (sig == SIGXFSZ)
            {
                fprintf(fresult, "OLE\nWEXITSTATUS() = %d, WTERMSIG() = %d (%s)\n", WEXITSTATUS(status), sig, strsignal(sig));
            }
            else if (usage.ru_maxrss > memory_limit)
            {
                fprintf(fresult, "MLE\nWEXITSTATUS() = %d, WTERMSIG() = %d (%s)\n", WEXITSTATUS(status), sig, strsignal(sig));
            }
            else
            {
                fprintf(fresult, "RE\nWEXITSTATUS() = %d, WTERMSIG() = %d (%s)\n", WEXITSTATUS(status), sig, strsignal(sig));
            }
        }

#ifdef LOG
        printf("memory_usage = %ld\n", usage.ru_maxrss);
        if (time_limit_exceeded_killed)
            printf("cpu_usage = %ld\n", time_limit_to_watch);
        else
            printf("cpu_usage = %ld\n", (usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec) / 1000);
#endif
        if (time_limit_exceeded_killed)
            fprintf(fresult, "%ld\n", time_limit_to_watch);
        else
            fprintf(fresult, "%ld\n", (usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec) / 1000);
        fprintf(fresult, "%ld\n", usage.ru_maxrss);

        fclose(fresult);
    }
    else
    {
#ifdef LOG
        puts("Entered child process.");
#endif

        // Child process

        if (time_limit)
        {
            struct rlimit lim;
            lim.rlim_cur = time_limit / 1000 + 1;
            if (time_limit % 1000 > 800)
                lim.rlim_cur += 1;
            lim.rlim_max = lim.rlim_cur + 1;
            setrlimit(RLIMIT_CPU, &lim);
        }

        if (memory_limit)
        {
            struct rlimit lim;
            lim.rlim_cur = memory_limit * 1024 * 2;
            lim.rlim_max = lim.rlim_cur + 1024;
            setrlimit(RLIMIT_AS, &lim);

            if (large_stack)
            {
                setrlimit(RLIMIT_STACK, &lim);
            }
        }

        if (output_limit)
        {
            struct rlimit lim;
            lim.rlim_cur = output_limit;
            lim.rlim_max = output_limit;
            setrlimit(RLIMIT_FSIZE, &lim);
        }

        if (process_limit)
        {
            struct rlimit lim;
            lim.rlim_cur = process_limit + 1;
            lim.rlim_max = process_limit + 1;
            setrlimit(RLIMIT_NPROC, &lim);
        }

#ifdef LOG
        puts("Entering target program...");
#endif

        if (strlen(file_stdin))
        {
            int fd = open(file_stdin, O_RDONLY);
            if (fd < 0)
            {
#ifdef LOG
                puts("Cannot open file_stdin...");
#endif
                return -1;
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
        }

        if (strlen(file_stdout))
        {
            int fd = open(file_stdout, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if (fd < 0)
            {
#ifdef LOG
                puts("Cannot open file_stdout...");
#endif
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }

        if (strlen(file_stderr))
        {
            int fd = open(file_stderr, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if (fd < 0)
            {
#ifdef LOG
                puts("Cannot open file_stderr...");
#endif
                return -1;
            }
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        if (!compile)
        {
            setegid(SANDBOX_GID);
            setuid(SANDBOX_UID);
        }
        // load rule
        if (!compile)
        {
            if (lang_id == 0 || lang_id == 1)
                c_cpp_rules(program, allow_write_file, allow_network_access);
            if (lang_id == 2)
                general_rules(program, allow_write_file);
        }

        execvp(program, program_argv);
    }
    return 0;
}
