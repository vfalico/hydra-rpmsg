/*
 * Dummy RPMSG routines for lproc.
 *
 * Copyright (C) 2014 Huawei Technologies, Inc.
 *
 * Ajo Jose Panoor <ajo.jose.panoor@huawei.com>
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

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/rpmsg.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/uio.h>
#include <linux/remoteproc.h>
#include "virtio_rpmsg.h"

#define MSG_SIZE	100

static void dummy_rpmsg_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, unsigned long src)
{
	static unsigned int reply_cnt;
	char buf[MSG_SIZE];
	int ret;

	len = snprintf(buf, MSG_SIZE, "Reply from lproc %u",++reply_cnt);
	ret = rpmsg_sendto(rpdev, buf, len + 1, src);
	if(ret)
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);
}

void create_dummy_channel_addr(struct rpmsg_channel_info *chinfo)
{
	strncpy(chinfo->name, "lproc", sizeof(chinfo->name));
	chinfo->src = 1048;
	chinfo->dst = RPMSG_ADDR_ANY;
}

void create_dummy_rpmsg_ept(struct virtproc_info *vrp,
					struct rpmsg_channel *rpdev,
					struct rpmsg_channel_info *chinfo)
{
	struct rpmsg_ns_msg msg;
	struct device *dev = &vrp->vdev->dev;
	struct rpmsg_endpoint *ept = NULL;
	int ret = 0;

	memset(&msg, 0, sizeof(msg));

	dev_dbg(dev,"%s: vrp %p\n",__func__,vrp);

	strncpy(msg.name, chinfo->name, sizeof(msg.name));

	msg.addr = chinfo->src;	//TODO hack till we use idr to get one.
	msg.flags |= RPMSG_NS_CREATE;

	ept = rpmsg_create_ept(rpdev, dummy_rpmsg_cb, NULL, rpdev->src);
	if (!ept) {
		dev_err(dev, "failed to create the ns ept\n");
	}
	ret = rpmsg_sendto(rpdev, &msg, sizeof(msg), RPMSG_NS_ADDR);
	if (ret)
		dev_err(dev, "failed to announce service %d\n", ret);

}

static unsigned int rpmsg_dummy_calc_reply_len(struct iovec iov[], int iov_count)
{
	int i;
	unsigned int len;

	for(i = 0, len = 0; i < iov_count; i++)
		len += iov[i].iov_len;

	return len;
}

static int rpmsg_dummy_var_reply(struct iovec iov[], int out, int in)
{
	struct rpmsg_hdr *recv_msg = iov[0].iov_base;
	struct rpmsg_hdr *reply_msg = iov[out].iov_base;
	static int reply_cnt;
	unsigned int len;

	BUG_ON(iov[out].iov_len < sizeof(struct rpmsg_hdr));

	len = rpmsg_dummy_calc_reply_len(iov + out, in);

	reply_msg->len = len - sizeof(struct rpmsg_hdr);
	reply_msg->flags = 0;
	reply_msg->src = recv_msg->dst;
	reply_msg->dst = recv_msg->src;
	reply_msg->reserved = 0;

	(void)snprintf((char *)reply_msg->data, len, "Variable size reply %d",
			++reply_cnt);
	return len;
}

void rpmsg_dummy_ap_var_size_recv_work(struct virtproc_info *vrp)
{
	struct device *dev = &vrp->vdev->dev;
	int in, out, ret;
	struct iovec *piov = vrp->piov;
	struct iovec *viov = vrp->viov;
	unsigned int len;
	u16 idx;

	idx = virtqueue_get_avail_buf(vrp->vvq, &out, &in, piov,
							ARRAY_SIZE(vrp->piov));
	if(idx < 0) {
		dev_err(dev, "virtqueue_get_avail_buf failed\n");
		return;
	}

	ret = rpmsg_phy_to_virt_iov(vrp, piov, viov, out + in, false);
	if(ret < 0) {
		dev_err(dev, "rpmsg_phy_to_virt_iov failed\n");
		return;
	}
	BUG_ON(ret != out + in);

	len = rpmsg_dummy_var_reply(viov, out, in);
	BUG_ON(len == 0);

	virtqueue_update_used_idx(vrp->vvq, idx, len);

	virtqueue_kick(vrp->vvq);

	ret = rpmsg_iounmap_iov(viov, out + in, false);
	BUG_ON(ret != out + in);
}
