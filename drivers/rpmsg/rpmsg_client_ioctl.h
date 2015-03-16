#ifndef _RPMSG_CLIENT_IOCTL_H_
#define _RPMSG_CLIENT_IOCTL_H_
#include <linux/types.h>

#define RPMSG_CLIENT_TEST_IOCTL		_IOWR('s', 1, void *)
#define RPMSG_CLIENT_CREATE_EPT_IOCTL	_IOWR('s', 2, unsigned int)
#define RPMSG_CLIENT_DESTROY_EPT_IOCTL	_IOWR('s', 3, unsigned int)

enum rpmsg_ptest {
	RPMSG_NULL_TEST,
	RPMSG_FIXED_SIZE_LATENCY,
	RPMSG_VAR_SIZE_LATENCY,
	RPMSG_USER_SPACE_IPC,
	RPMSG_MAX_TEST
};

struct rpmsg_test_args {
	int remote_cpu;
	int test_type;
	int num_runs;
	int sbuf_size;
	int rbuf_size;
	unsigned int ept_addr;
	int wait;
};

#endif //_RPMSG_CLIENT_IOCTL_H_
