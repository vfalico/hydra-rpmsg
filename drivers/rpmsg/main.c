#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <poll.h>
#include <features.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "rpmsg_client_ioctl.h"

#define DEV_NAME	"/dev/crpmsg"
#define PATH_MAX	80
#define PING		1

struct rpmsg_test_args {
	int remote_cpu;
	int test_type;
	int num_runs;
	int sbuf_size;
	int rbuf_size;
	int rpmsg_ept;
	int wait;
};


static void print_usage(void)
{
	fprintf(stderr, "Usage: test_rpmsg [-c cpu] [-t test_type] "
			"[-n num_runs] \n[-s sbuf_size] [-r rbuf_siz]"
			" [-e rpmsg_ept_addr] [-w wait]\n");
}

#define TEST_INPUT_OPTS		"c:t:n:s:r:e:w:"

static void dump_args(struct rpmsg_test_args *targs)
{
	printf("args: c=%d, t=%d, n=%d, s=%d, r=%d, e=%d w=%d\n",
			targs->remote_cpu, targs->test_type,
			targs->num_runs, targs->sbuf_size,
			targs->rbuf_size, targs->rpmsg_ept, targs->wait);
}

static void rpmsg_validate_test_args(struct rpmsg_test_args *targs)
{
	dump_args(targs);
	assert(!((targs->remote_cpu == -1) && (targs->rpmsg_ept ==  -1)));
	assert(!(targs->test_type == -1));
	assert(!(targs->sbuf_size == 0));
	assert(!(targs->rbuf_size == 0));
}


static struct rpmsg_test_args *rpmsg_get_test_args(int argc, char *argv[])
{
	struct rpmsg_test_args *targs;
	int opt;

	targs = malloc(sizeof(*targs));
	targs->remote_cpu = -1;
	targs->test_type = -1;
	targs->rpmsg_ept = -1;
	targs->num_runs = 1;
	targs->wait = 0;

	while((opt = getopt(argc, argv, TEST_INPUT_OPTS)) != -1) {
		switch (opt) {
			case 'c':
				targs->remote_cpu = atoi(optarg);
				break;
			case 't':
				targs->test_type = atoi(optarg);
				break;
			case 'n':
				targs->num_runs = atoi(optarg);
				break;
			case 's':
				targs->sbuf_size = atoi(optarg);
				break;
			case 'r':
				targs->rbuf_size = atoi(optarg);
				break;
			case 'e':
				targs->rpmsg_ept = atoi(optarg);
				break;
			case 'w':
				targs->wait = atoi(optarg);
				break;
			case '?':
			default:
				print_usage();
				free(targs);
				exit(EXIT_FAILURE);
		}
	}
	return targs;
}

#define MSG_SIZE	256

int main(int argc, char *argv[])
{
	char path[PATH_MAX];
	int fd, ret, id = 0, i;
	struct rpmsg_test_args *targs;
	unsigned long addr;
	char str[MSG_SIZE];

	snprintf(path, PATH_MAX, DEV_NAME"%d", id);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		printf("Could not open %s %s\n", path, strerror(errno));
		return;
	}
#ifdef PING
	targs = rpmsg_get_test_args(argc, argv);

	rpmsg_validate_test_args(targs);

	addr = targs->rpmsg_ept;
	ret = ioctl(fd, RPMSG_CLIENT_CREATE_EPT_IOCTL, addr);
	if (ret < 0) {
		printf(" IOCTL failed %s %s\n", path, strerror(errno));
		return;
	}
	ret = ioctl(fd, RPMSG_CLIENT_TEST_IOCTL, (void *)targs);
	if (ret < 0) {
		printf(" IOCTL failed %s %s\n", path, strerror(errno));
		return;
	}
	if(!targs->wait) while(1);
	ret = ioctl(fd, RPMSG_CLIENT_DESTROY_EPT_IOCTL, addr);
	if (ret < 0) {
		printf(" IOCTL failed %s %s\n", path, strerror(errno));
		return;
	}
#else
	if (write(fd, str, MSG_SIZE) < MSG_SIZE){
		printf("Could not write to %s %s\n", path, strerror(errno));
		return;
	}

	if (read(fd, str, MSG_SIZE) < 0){
		printf("Could not read from %s %s\n", path, strerror(errno));
		return;
	}
	printf("%s\n",str);
#endif
}
