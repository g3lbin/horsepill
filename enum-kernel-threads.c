#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>

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
		printf("found kernel thread: \"%s\"\n", newpidname);
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

	if ((dirp = opendir("/proc")) == NULL) {
		printf("couldn't open '/proc'\n");
		exit(EXIT_FAILURE);
	}

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

	if (errno != 0) {
		printf("error reading directory\n");
		exit(EXIT_FAILURE);
	}
	(void) closedir(dirp);
        return i;
}

void main()
{
        int i;
        int num;
        char *kthreads[1024];

        num = enumerate_kernel_threads(kthreads);
        printf("\n\n%d\n", num);

        for (i = 0; i < num; i++) {
                free(kthreads[i]);
        }
}