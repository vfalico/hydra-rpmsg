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

#define MSG		"hello world!"

enum rpmsg_ptest {
	RPMSG_NULL_TEST,
	RPMSG_FIXED_SIZE_LATENCY,
	RPMSG_VAR_SIZE_LATENCY,
	RPMSG_MAX_TEST
};

//#define VAR_TEST	0

#ifdef VAR_TEST

#define RLEN		(8192)
#define SLEN		(RLEN * 2)
#define PTYPE		RPMSG_VAR_SIZE_LATENCY
#define MSG_LIMIT	200

#else

#define RLEN		(512 - sizeof(struct rpmsg_hdr))
#define SLEN		RLEN
#define PTYPE		RPMSG_FIXED_SIZE_LATENCY
#define MSG_LIMIT	200

#endif

#define MAX_TEST_STATE		3

struct rpmsg_perf_timestamp {
	ktime_t start_time;
	ktime_t end_time;
};

struct rpmsg_perf_stats {
	u32 nsend;
	u32 nrecv;
	u64 tmin;
	u64 tmax;
	u64 tavg;
	u64 tsum;
	u64 triptime;
	struct rpmsg_perf_timestamp timestamps[MAX_TEST_STATE];
};

struct rpmsg_perf_stats gstats;

#define G (*(struct rpmsg_perf_stats*)&gstats)
#define nsend		(G.nsend)
#define nrecv		(G.nrecv)
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

#define LOG_TIME(x)	do {	\
	x = ktime_get_real();	\
} while(0)

#define UPDATE_ROUND_TRIP_STATS()	do {		\
	triptime = ktime_to_ns(recv_end_time) -		\
			ktime_to_ns(send_start_time);	\
	triptime = triptime/1000;			\
	tsum += triptime;				\
	if(triptime < tmin)				\
		tmin = triptime;			\
	if(triptime > tmax)				\
		tmax = triptime;			\
							\
}while(0)

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

struct rpmsg_perf grpt = {
	.rbuf =	NULL,
	.sbuf =	NULL,
	.rlen =	RLEN,
	.slen =	SLEN,
	.type = PTYPE,
	.rpdev = NULL,
	.cb = NULL,
};

static void rpmsg_perf_free_resources(struct rpmsg_perf *rpt)
{
	vfree(rpt->rbuf);
	vfree(rpt->sbuf);
}

static void rpmsg_perf_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct rpmsg_perf *rpt = &grpt; // later we should use priv for this.

	LOG_TIME(recv_end_time);

	nrecv++;

	UPDATE_ROUND_TRIP_STATS();

	dev_info(&rpdev->dev, "%d bytes from 0x%x seq=%d rtt=%u.%03u ms\n",
			len, src, nrecv, triptime / 1000, triptime % 1000);

	rpt->cb(rpdev, data, len, (void *)rpt, src);
}

static void rpmsg_perf_fixed_size_cb(struct rpmsg_channel *rpdev, void *data,
	       					int len, void *priv, u32 src)
{
	int ret;
	struct rpmsg_perf *rpt = priv;

#if 0
	print_hex_dump(KERN_DEBUG, __func__, DUMP_PREFIX_NONE, 16, 1,
		       data, len,  true);
#endif
	if (nrecv >= MSG_LIMIT) {
		dev_info(&rpdev->dev, "%s goodbye!\n",__func__);
		return;
	}

	LOG_TIME(send_start_time);

	ret = rpmsg_send(rpdev, rpt->sbuf, rpt->slen);
	if (ret)
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);

	LOG_TIME(send_end_time);
	nsend++;
}

static void rpmsg_perf_var_size_cb(struct rpmsg_channel *rpdev, void *data,
	       					int len, void *priv, u32 src)
{
	int ret;
	static int rx_count;
	struct rpmsg_perf *rpt = priv;

#if 0
	print_hex_dump(KERN_DEBUG, __func__, DUMP_PREFIX_NONE, 16, 1,
		       data, len,  true);

#endif
	if (nrecv >= MSG_LIMIT) {
		dev_info(&rpdev->dev, "%s goodbye!\n",__func__);
		return;
	}

	LOG_TIME(send_start_time);

	ret = rpmsg_send_recv(rpdev, rpt->sbuf, rpt->slen, rpt->rbuf, rpt->rlen);
	if (ret)
		dev_err(&rpdev->dev, "rpmsg_send_recv failed: %d\n", ret);

	LOG_TIME(send_end_time);
	nsend++;
}

static struct rpmsg_perf * rpmsg_perf_test_trigger(struct rpmsg_channel *rpdev)
{
	int ret = 0;
	struct rpmsg_perf *rpt = &grpt;

	rpt->rpdev = rpdev;
	rpt->type = PTYPE;

	rpt->sbuf = vmalloc(grpt.slen);
	rpt->rbuf = vmalloc(grpt.rlen);

	LOG_TIME(send_start_time);
	switch(rpt->type) {
		case RPMSG_FIXED_SIZE_LATENCY:
			rpt->cb = rpmsg_perf_fixed_size_cb;
			ret = rpmsg_send(rpdev, rpt->sbuf, rpt->slen);
			if (ret) {
				dev_err(&rpdev->dev, "rpmsg_send failed: %d\n",
					       	ret);
				return NULL;
			}
			break;
		case RPMSG_VAR_SIZE_LATENCY:
			rpt->cb = rpmsg_perf_var_size_cb;
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
	return rpt;
}

static int rpmsg_perf_probe(struct rpmsg_channel *rpdev)
{
	int ret = 0;
	struct rpmsg_perf *rpt;

	dev_info(&rpdev->dev, "new channel: 0x%lx -> 0x%lx!\n",
					rpdev->src, rpdev->dst);
	rpt = rpmsg_perf_test_trigger(rpdev);
	return ret;
}

static void __devexit rpmsg_perf_remove(struct rpmsg_channel *rpdev)
{
	rpmsg_perf_free_resources(&grpt); // FIXME
	dev_info(&rpdev->dev, "rpmsg perf test driver is removed\n");
}

static struct rpmsg_device_id rpmsg_driver_sample_id_table[] = {
	{ .name	= "lproc" },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpmsg_driver_sample_id_table);

static struct rpmsg_driver rpmsg_perf_test = {
	.drv.name	= KBUILD_MODNAME,
	.drv.owner	= THIS_MODULE,
	.id_table	= rpmsg_driver_sample_id_table,
	.probe		= rpmsg_perf_probe,
	.callback	= rpmsg_perf_cb,
	.remove		= __devexit_p(rpmsg_perf_remove),
};

static int __init rpmsg_perf_test_init(void)
{
	return register_rpmsg_driver(&rpmsg_perf_test);
}
module_init(rpmsg_perf_test_init);

static void __exit rpmsg_perf_test_fini(void)
{
	unregister_rpmsg_driver(&rpmsg_perf_test);
}
module_exit(rpmsg_perf_test_fini);

MODULE_DESCRIPTION("Remote processor messaging perf test driver");
MODULE_LICENSE("GPL v2");
