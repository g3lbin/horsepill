#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/mount.h>

#define STACK_SIZE (1024 * 1024)    /* Stack size for cloned child */

#define err_exit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                               } while (0)

int do_work(void *num)
{
        long n = (long)num;
        const int mountflags = MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME;

        printf("Child '%d' spawned with argument: '%ld'\n", getpid(), n);
        
        if (mount("none", "/proc", "", MS_REC | MS_PRIVATE, NULL) < 0)
                goto err;
        if (mount("proc", "/proc", "proc", mountflags, NULL) < 0)
                goto err;

        system("ps aux");
        
        return 0;
err:
	err_exit("Cannot remount '/proc'");
}

void main()
{
        char *stack;
        char *stack_top;
        int init_pid;
        long arg = 7;

        /* Allocate memory to be used for the stack of the child. */

        stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        if (stack == MAP_FAILED)
                err_exit("mmap");

        stack_top = stack + STACK_SIZE;  /* Assume stack grows downward */

        init_pid = clone(do_work, stack_top, CLONE_NEWPID | CLONE_NEWNS |
                        SIGCHLD, (void *)arg);
        if (init_pid == -1)
                err_exit("clone");
        printf("Parent '%d' is waiting for the child '%d'...\n", getpid(), init_pid);
        
        if (waitpid(init_pid, NULL, 0) == -1)    /* Wait for child */
                err_exit("waitpid");
        printf("Child has terminated!\n");

        munmap(stack, STACK_SIZE);
        exit(EXIT_SUCCESS);
}
