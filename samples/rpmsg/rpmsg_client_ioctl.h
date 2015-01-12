#ifndef _RPMSG_CLIENT_IOCTL_H_
#define _RPMSG_CLIENT_IOCTL_H_
#include <linux/types.h>

#define RPMSG_CLIENT_TEST_IOCTL		_IOWR('s', 1, void *)
#define RPMSG_CLIENT_CREATE_EPT_IOCTL	_IOWR('s', 2, unsigned long)

#endif //_RPMSG_CLIENT_IOCTL_H_
