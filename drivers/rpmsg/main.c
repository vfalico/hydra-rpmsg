#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
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
#define PMAX		80

char path[PMAX];

static void print_usage(void)
{
	fprintf(stderr, "Usage: test_rpmsg [-c cpu] [-t test_type] "
			"[-n num_runs] \n[-s sbuf_size] [-r rbuf_siz]"
			" [-e ept_addr] [-w wait]\n");
	fprintf(stderr, "test types: (1) ping fix size\n"
			"(2) ping var size\n(3) user space ipc test\n");
}

#define TEST_INPUT_OPTS		"c:t:n:s:r:e:w:h"
void __random(int *buf, int len)
{
	unsigned int seed, i, val, times = len / sizeof(int);
	FILE* urandom = fopen("/dev/urandom", "r");
	fread(&seed, sizeof(int), 1, urandom);
	fclose(urandom);
	srand(seed);

	for(i=0; i < times; i++)
		buf[i] = rand();
}

static void dump_args(struct rpmsg_test_args *targs)
{
	printf("args: c=%d, t=%d, n=%d, s=%d, r=%d, e=%d w=%d\n",
			targs->remote_cpu, targs->test_type,
			targs->num_runs, targs->sbuf_size,
			targs->rbuf_size, targs->ept_addr, targs->wait);
}

static void rpmsg_validate_ping_args(struct rpmsg_test_args *targs)
{
	dump_args(targs);
	assert(!((targs->remote_cpu == -1) && (targs->ept_addr ==  UINT_MAX)));
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
	targs->ept_addr = UINT_MAX;
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
				targs->ept_addr = atoi(optarg);
				break;
			case 'w':
				targs->wait = atoi(optarg);
				break;
			case '?':
			case 'h':
			default:
				print_usage();
				free(targs);
				exit(EXIT_FAILURE);
		}
	}
	return targs;
}
void __dump_buf(int *buf, int len)
{
	int i, times, t = len/sizeof(int);
	times = t < 16 ? t : 16;

	for(i=0; i < times; i+=4) {
		printf("crpmsg[%d]: %x %x %x %x %x\n",i, buf[i], buf[i+1], buf[i+2], buf[i+3]);
	}
}

void rpmsg_multikern_ipc_test(int fd, struct rpmsg_test_args *targs)
{
	void *sbuf = NULL, *rbuf = NULL;
	int i,ret;

	if(targs->ept_addr) {
		ret = ioctl(fd, RPMSG_CLIENT_CREATE_EPT_IOCTL, targs->ept_addr);
		if (ret < 0) {
			printf(" IOCTL failed %s %s\n", path, strerror(errno));
			return;
		}
	}

	if (targs->sbuf_size) {
		sbuf = malloc(targs->sbuf_size);
		for(i = 0; i < targs->num_runs; i++) {
			__random(sbuf, targs->sbuf_size);
			if (write(fd, sbuf, targs->sbuf_size) < targs->sbuf_size) {
				printf("Could not write to %s %s\n", path, strerror(errno));
				goto err;
			}
		}
	}

	if(targs->rbuf_size) {
		rbuf = malloc(targs->rbuf_size);
		for(i = 0; i < targs->num_runs; i++) {
			if (read(fd, rbuf, targs->rbuf_size) < 0){
				printf("Could not read from %s %s\n", path, strerror(errno));
				goto err;
			}
			__dump_buf(rbuf, targs->rbuf_size);
		}
	}
err:
	if(rbuf) free(rbuf);
	if(sbuf) free(sbuf);
}

int main(int argc, char *argv[])
{
	int fd, ret, id = 0;
	struct rpmsg_test_args *targs;
	unsigned int addr;

	snprintf(path, PATH_MAX, DEV_NAME"%d", id);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		printf("Could not open %s %s\n", path, strerror(errno));
		return;
	}

	targs = rpmsg_get_test_args(argc, argv);

	switch(targs->test_type) {
		case RPMSG_FIXED_SIZE_LATENCY:
		case RPMSG_VAR_SIZE_LATENCY:
			rpmsg_validate_ping_args(targs);
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
			break;
		case RPMSG_USER_SPACE_IPC:
			rpmsg_multikern_ipc_test(fd, targs);
			break;
		default:
			printf("Invalid test type %d.\n(1) ping fix size\n"
				"(2) ping var size\n(3) user space ipc test\n",
			       	targs->test_type);
			break;
	}
}
