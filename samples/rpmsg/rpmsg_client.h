#ifndef _RPMSG_CLIENT_H
#define _RPMSG_CLIENT_H

#include <linux/types.h>
#include <asm/msr.h>
#include <linux/rpmsg.h>

#define RPMSG_KTIME		1
#define MAX_TEST_STATE		3

struct rpmsg_client_timestamp {
	unsigned long start_time;
	unsigned long end_time;
};

struct rpmsg_client_stats {
	unsigned int nsend;
	unsigned int nrecv;
	unsigned long bsend;
	unsigned long brecv;
	unsigned long tmin;
	unsigned long tmax;
	unsigned long tavg;
	unsigned long tsum;
	unsigned long triptime;
	struct rpmsg_client_timestamp timestamps[MAX_TEST_STATE];
};

enum rpmsg_ptest {
	RPMSG_NULL_TEST,
	RPMSG_FIXED_SIZE_LATENCY,
	RPMSG_VAR_SIZE_LATENCY,
	RPMSG_MAX_TEST
};

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
	rdtscll(x);				\
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
	unsigned long totalbytes;			\
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

struct rpmsg_test_args {
	int remote_cpu;
	int test_type;
	int num_runs;
	int sbuf_size;
	int rbuf_size;
	int rpmsg_ept;
};

struct rpmsg_client_device {
	int id;
	void *priv;
	struct cdev cdev;
	struct rpmsg_channel *rpdev;
	struct list_head recvqueue;
	wait_queue_head_t recvwait;
};

struct rpmsg_client_vdev {
	struct rpmsg_client_device *rcdev;
	struct rpmsg_endpoint *ept;
	unsigned long src;
};

struct rpmsg_recv_blk{
	int len;
	struct list_head list;
	unsigned long addr;
	unsigned short *data;
};

void rpmsg_client_ping(struct rpmsg_client_vdev *rvdev,
		 				struct rpmsg_test_args *targs);
void rpmsg_client_cb(struct rpmsg_channel *rpdev, void *data, int len,
							void *priv, u32 src);
#endif //_RPMSG_CLIENT_H
