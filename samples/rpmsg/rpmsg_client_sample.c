/*
 * Remote processor messaging - Performance test
 *
 * Ajo Jose Panoor <ajo.jose.panoor@huawai.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include "rpmsg_client_ioctl.h"

enum rpmsg_ptest {
	RPMSG_NULL_TEST,
	RPMSG_FIXED_SIZE_LATENCY,
	RPMSG_VAR_SIZE_LATENCY,
	RPMSG_MAX_TEST
};

#define VAR_TEST	1
#define RPMSG_KTIME	1

#ifdef VAR_TEST

#define RLEN		(2048)
#define SLEN		(RLEN)
#define PTYPE		RPMSG_VAR_SIZE_LATENCY
#define MSG_LIMIT	200

#else

#define RLEN		(256 + sizeof(struct rpmsg_hdr))
#define SLEN		(RLEN - sizeof(struct rpmsg_hdr))
#define PTYPE		RPMSG_FIXED_SIZE_LATENCY
#define MSG_LIMIT	200

#endif

#define MAX_TEST_STATE		3

struct rpmsg_client_timestamp {
	u64 start_time;
	u64 end_time;
};

struct rpmsg_client_stats {
	u32 nsend;
	u32 nrecv;
	u64 bsend;
	u64 brecv;
	u64 tmin;
	u64 tmax;
	u64 tavg;
	u64 tsum;
	s64 triptime;
	struct rpmsg_client_timestamp timestamps[MAX_TEST_STATE];
};

struct rpmsg_client_stats gstats;

#define G (*(struct rpmsg_client_stats*)&gstats)
#define nsend		(G.nsend)
#define nrecv		(G.nrecv)
#define bsend		(G.bsend)
#define	brecv		(G.brecv)
#define tmin		(G.tmin)
#define tmax		(G.tmax)
#define tavg		(G.tavg)
#define tsum		(G.tsum)
#define triptime	(G.triptime)
#define send_start_time	(G.timestamps[0].start_time)
#define send_end_time	(G.timestamps[0].end_time)
#define recv_start_time (G.timestamps[1].start_time)
#define recv_end_time	(G.timestamps[1].end_time)
#define test_start_time (G.timestamps[2].start_time)
#define test_end_time	(G.timestamps[2].end_time)

#define INIT_STATS()	do {	\
	memset(&gstats, 0, sizeof(struct rpmsg_client_stats));	\
	tmin = UINT_MAX;					\
} while(0)

#ifdef	RPMSG_KTIME
#define LOG_TIME(x)	do {			\
	x = ktime_to_ns(ktime_get_real());	\
} while(0)
#else
#define LOG_TIME(x)	do {			\
	x = rdtscll();				\
} while(0)
#endif

#define UPDATE_ROUND_TRIP_STATS()	do {		\
	t = triptime = recv_end_time - send_start_time;	\
	triptime = triptime/1000;			\
	tsum += triptime;				\
	if(triptime < tmin)				\
		tmin = triptime;			\
	if(triptime > tmax)				\
		tmax = triptime;			\
} while(0)

#define PRINT_TEST_SUMMARY()	do {			\
	uint64_t totalbytes;				\
	totalbytes = bsend + brecv;			\
	tsum = (tsum/1000);				\
	printk("\n--- rpmsg ping statistics ---\n"	\
			"%lu packets transmitted, "	\
			"%lu packets received, "	\
			"%lu bytes transfered, "	\
			"%u bytes/ms. \n",		\
			nsend, nrecv, totalbytes,	\
			(totalbytes / tsum));		\
	if (tmin != UINT_MAX) {				\
		tavg = tsum / nrecv;			\
		printk("round-trip min/avg/max = "	\
			"%u.%03u/%u.%03u/%u.%03u ms\n",	\
			tmin / 1000, tmin % 1000,	\
			tavg / 1000, tavg % 1000,	\
			tmax / 1000, tmax % 1000);	\
	}						\
} while(0)

struct rpmsg_perf {
	char *rbuf;
	char *sbuf;
	int rlen;
	int slen;
	enum rpmsg_ptest type;
	struct rpmsg_channel *rpdev;
	void (*cb)(struct rpmsg_channel *rpdev, void *data, int len,
			void *priv, u32 src);
};

static struct rpmsg_perf grpt = {
	.rbuf =	NULL,
	.sbuf =	NULL,
	.rlen =	RLEN,
	.slen =	SLEN,
	.type = PTYPE,
	.rpdev = NULL,
	.cb = NULL,
};

/* ID allocator for RPMSG client devices */
static struct ida g_rpmsg_client_ida;
/* Class of RPMSG client devices for sysfs accessibility. */
static struct class *g_rpmsg_client_class;
/* Base device node number for rpmsg client devices */
static dev_t g_rpmsg_client_devno;

#define RPMSG_CLIENT_MAX_NUM_DEVS		256
#define RPMSG_CLIENT_DEV			"crpmsg"

static const char rpmsg_client_driver_name[] = "rpmsg_client";

struct rpmsg_client_device {
	int id;
	void *priv;
	struct cdev cdev;
	struct rpmsg_channel *rpdev;
};
static struct rpmsg_client_device *rcdev;

struct rpmsg_client_vdev {
	struct rpmsg_client_device *rcdev;
};

int rpmsg_open(struct inode *inode, struct file *f);
int rpmsg_release(struct inode *inode, struct file *f);
long rpmsg_ioctl(struct file *f, unsigned int cmd, unsigned long arg);

int rpmsg_open(struct inode *inode, struct file *f)
{
	struct rpmsg_client_vdev *rvdev;
	struct rpmsg_client_device *rcdev = container_of(inode->i_cdev,
			 struct rpmsg_client_device, cdev);

	printk(KERN_INFO "%s\n",__func__);
	rvdev = kmalloc(sizeof(*rvdev), GFP_KERNEL);
	if(!rvdev)
		return -ENOMEM;
	rvdev->rcdev = rcdev;
	f->private_data = rvdev;
	return 0;
}

int rpmsg_release(struct inode *inode, struct file *f)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	printk(KERN_INFO "%s\n",__func__);
	kfree(rvdev);
	return 0;
}

long rpmsg_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	void __user *argp = (void __user *)arg;

	printk(KERN_INFO "%s\n",__func__);
	switch (cmd) {
		case RPMSG_CLIENT_DUMMY_IOCTL:
			printk(KERN_INFO "%s cmd: %d argp %p\n", __func__, cmd,
					 argp);
			break;
		default:
			printk(KERN_INFO "%s cmd: %d ioctl failed\n", __func__,
					 cmd);
			return -ENOIOCTLCMD;
	}
	return 0;
}

static const struct file_operations rpmsg_client_fops = {
	.open = rpmsg_open,
	.release = rpmsg_release,
	.unlocked_ioctl = rpmsg_ioctl,
	.owner = THIS_MODULE,
};

static void rpmsg_client_free_resources(struct rpmsg_perf *rpt)
{
	vfree(rpt->rbuf);
	vfree(rpt->sbuf);
}

static void inline __fill_data(char *buf, int len)
{
	memset(buf, 'a', len);
}

static void rpmsg_client_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	s64 t;
	struct rpmsg_perf *rpt = &grpt; // later we should use priv for this.

	LOG_TIME(recv_end_time);

	nrecv++;
	brecv += (len + sizeof(struct rpmsg_hdr));

	UPDATE_ROUND_TRIP_STATS();

	dev_info(&rpdev->dev, "%d bytes from 0x%x seq=%d t= %ld rtt=%ld us\n",
			len, src, nrecv, t, triptime);

	rpt->cb(rpdev, data, len, (void *)rpt, src);
}

static void rpmsg_client_fixed_size_cb(struct rpmsg_channel *rpdev, void *data,
	       					int len, void *priv, u32 src)
{
	int ret;
	struct rpmsg_perf *rpt = priv;

#if 0
	print_hex_dump(KERN_DEBUG, __func__, DUMP_PREFIX_NONE, 16, 1,
		       data, len,  true);
#endif
	if (nrecv >= MSG_LIMIT) {
		PRINT_TEST_SUMMARY();
		return;
	}

	LOG_TIME(send_start_time);

	__fill_data((char *)(rpt->sbuf + sizeof(struct rpmsg_hdr)),
					(rpt->slen - sizeof(struct rpmsg_hdr)));
	ret = rpmsg_send(rpdev, rpt->sbuf, rpt->slen);
	if (ret)
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);

	LOG_TIME(send_end_time);
	nsend++;
	bsend += rpt->slen;
}

static void rpmsg_client_var_size_cb(struct rpmsg_channel *rpdev, void *data,
	       					int len, void *priv, u32 src)
{
	int ret;
	struct rpmsg_perf *rpt = priv;

#if 0
	print_hex_dump(KERN_DEBUG, __func__, DUMP_PREFIX_NONE, 16, 1,
		       data, len,  true);

#endif
	if (nrecv >= MSG_LIMIT) {
		PRINT_TEST_SUMMARY();
		return;
	}

	LOG_TIME(send_start_time);

	__fill_data((char *)(rpt->sbuf + sizeof(struct rpmsg_hdr)),
					(rpt->slen - sizeof(struct rpmsg_hdr)));
	ret = rpmsg_send_recv(rpdev, rpt->sbuf, rpt->slen, rpt->rbuf, rpt->rlen);
	if (ret)
		dev_err(&rpdev->dev, "rpmsg_send_recv failed: %d\n", ret);

	LOG_TIME(send_end_time);
	nsend++;
	bsend += rpt->slen;
}

static struct rpmsg_perf *rpmsg_client_trigger(struct rpmsg_channel *rpdev)
{
	int ret = 0;
	struct rpmsg_perf *rpt = &grpt;

	INIT_STATS();
	rpt->rpdev = rpdev;
	rpt->type = PTYPE;
	rpt->sbuf = vmalloc(grpt.slen);
	rpt->rbuf = vmalloc(grpt.rlen);
	LOG_TIME(send_start_time);
	switch(rpt->type) {
		case RPMSG_FIXED_SIZE_LATENCY:
			rpt->cb = rpmsg_client_fixed_size_cb;
			ret = rpmsg_send(rpdev, rpt->sbuf, rpt->slen);
			if (ret) {
				dev_err(&rpdev->dev, "rpmsg_send failed: %d\n",
					       	ret);
				return NULL;
			}
			break;
		case RPMSG_VAR_SIZE_LATENCY:
			rpt->cb = rpmsg_client_var_size_cb;
			ret = rpmsg_send_recv(rpdev, rpt->sbuf, rpt->slen,
					 rpt->rbuf, rpt->rlen);
			if (ret) {
				dev_err(&rpdev->dev, "rpmsg_send_recv failed:"
						" %d\n", ret);
				return NULL;
			}
			break;
		case RPMSG_NULL_TEST:
		default:
			dev_err(&rpdev->dev, "unknown rpmsg test type\n");
			return NULL;
	}
	LOG_TIME(send_end_time);
	nsend++;
	bsend += rpt->slen;
	return rpt;
}

static int rpmsg_client_probe(struct rpmsg_channel *rpdev)
{
	int ret = 0;
	struct rpmsg_perf *rpt;
	struct device *device = NULL;
	dev_t devno;
	dev_info(&rpdev->dev, "new channel: 0x%lx -> 0x%lx!\n",
					rpdev->src, rpdev->dst);
	rcdev = kzalloc(sizeof(*rcdev), GFP_KERNEL);
	if (IS_ERR(rcdev)) {
		ret = PTR_ERR(rcdev);
		dev_err(&rpdev->dev, "rcdev kmalloc failed %d\n",ret);
		return ret;
	}
	rcdev->id = ida_simple_get(&g_rpmsg_client_ida, 0,
		       		RPMSG_CLIENT_MAX_NUM_DEVS, GFP_KERNEL);
	if (rcdev->id < 0) {
		ret = rcdev->id;
		dev_err(&rpdev->dev, "ida_simple_get failed %d\n", ret);
		goto ida_fail;
	}
	devno = MKDEV(MAJOR(g_rpmsg_client_devno), rcdev->id);
	cdev_init(&rcdev->cdev, &rpmsg_client_fops);
	rcdev->cdev.owner = THIS_MODULE;
	ret = cdev_add(&rcdev->cdev, devno, 1);
	if (ret) {
		dev_err(&rpdev->dev, "cdev_add err id %d ret %d\n",
								rcdev->id, ret);
		goto cdevice_init_fail;
	}
	device = device_create(g_rpmsg_client_class, NULL, devno, NULL,
			 RPMSG_CLIENT_DEV "%d", rcdev->id);
	if (IS_ERR(device)) {
		ret = PTR_ERR(device);
		dev_err(&rpdev->dev, "devce_create failed with %d while trying"
				"to create %s%d", RPMSG_CLIENT_DEV, rcdev->id);
		goto cdevice_create_fail;
	}
	rcdev->rpdev = rpdev;
	dev_info(&rpdev->dev, "device %s%d created!\n", RPMSG_CLIENT_DEV,
								rcdev->id);
	//rpt = rpmsg_client_trigger(rpdev);
	return ret;

cdevice_create_fail:
	cdev_del(&rcdev->cdev);
cdevice_init_fail:
	ida_simple_remove(&g_rpmsg_client_ida, rcdev->id);
ida_fail:
	kfree(rcdev);
	return ret;
}

static void __devexit rpmsg_client_remove(struct rpmsg_channel *rpdev)
{
	rpmsg_client_free_resources(&grpt); // FIXME
		dev_info(&rpdev->dev, "rpmsg perf test driver is removed\n");
}

static struct rpmsg_device_id rpmsg_driver_sample_id_table[] = {
	{ .name	= "lproc" },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpmsg_driver_sample_id_table);

static struct rpmsg_driver rpmsg_client = {
	.drv.name	= KBUILD_MODNAME,
	.drv.owner	= THIS_MODULE,
	.id_table	= rpmsg_driver_sample_id_table,
	.probe		= rpmsg_client_probe,
	.callback	= rpmsg_client_cb,
	.remove		= __devexit_p(rpmsg_client_remove),
};

static int __init rpmsg_client_init(void)
{
	int ret = 0;

	ret = alloc_chrdev_region(&g_rpmsg_client_devno, 0,
		RPMSG_CLIENT_MAX_NUM_DEVS, rpmsg_client_driver_name);
	if (ret) {
		printk(KERN_ERR "alloc_chrdev_region failed ret %d\n", ret);
		return ret;
	}
	g_rpmsg_client_class = class_create(THIS_MODULE,
						rpmsg_client_driver_name);
	if (IS_ERR(g_rpmsg_client_class)) {
		ret = PTR_ERR(g_rpmsg_client_class);
		printk(KERN_ERR "class_create failed ret %d\n", ret);
		goto cleanup_chrdev;
	}
	ida_init(&g_rpmsg_client_ida);
	ret = register_rpmsg_driver(&rpmsg_client);
	if(ret) {
		 printk(KERN_ERR "register_rpmsg_driver failed %d\n",ret);
		 goto cleanup_class;
	}
	return ret;
cleanup_class:
	class_destroy(g_rpmsg_client_class);
cleanup_chrdev:
	unregister_chrdev_region(g_rpmsg_client_devno,
						RPMSG_CLIENT_MAX_NUM_DEVS);
	return ret;
}
module_init(rpmsg_client_init);

static void __exit rpmsg_client_fini(void)
{
	ida_simple_remove(&g_rpmsg_client_ida, rcdev->id);
	cdev_del(&rcdev->cdev);
	device_destroy(g_rpmsg_client_class, MKDEV(MAJOR(g_rpmsg_client_devno),
				rcdev->id));
	class_destroy(g_rpmsg_client_class);
	unregister_chrdev_region(g_rpmsg_client_devno,
						RPMSG_CLIENT_MAX_NUM_DEVS);
	unregister_rpmsg_driver(&rpmsg_client);
}
module_exit(rpmsg_client_fini);

MODULE_DESCRIPTION("Remote processor messaging perf test driver");
MODULE_LICENSE("GPL v2");
