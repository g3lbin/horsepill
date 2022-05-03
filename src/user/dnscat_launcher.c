#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define DNSCAT_PATH "./dnscat"

static char *const ARGV0 = "dnscat\0";
static char *const ARGV1 = "--dns\0";
static char *const ARGV2 = "server=127.0.0.1,port=53\0";
static char *const ARGV3 = "--secret=5100a1e43a193b60ba720ada295189a6\0";

static pid_t run_dnscat_client()
{
        int ret;
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

		// close(0);
		// close(1);
		// close(2);

		// YOLO(open("/dev/null", O_RDONLY));
		// YOLO(open("/dev/null", O_WRONLY));
		// YOLO(open("/dev/null", O_RDWR));

		ret = execv(DNSCAT_PATH, argv);

		printf("couldn't run dnscat!\n");
		exit(EXIT_FAILURE);
	}
	return pid;
}

void main()
{
        pid_t child = run_dnscat_client();
        waitpid(child, NULL, 0);
        printf("bye\n");
}