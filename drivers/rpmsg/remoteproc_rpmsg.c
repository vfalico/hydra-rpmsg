/*
 * Helper routines for RPMSG over remoteproc.
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

extern struct workqueue_struct *rpmsg_virtio_cfg_wq;
extern struct workqueue_struct *rpmsg_virtio_rcv_wq;

void *__rpmsg_ptov(struct virtproc_info *vrp, unsigned long addr, size_t len)
{
	unsigned offset;
	unsigned long va;
	struct pool_info *rp_info = &vrp->rp_info;

	/*
	 * HACK .. till be have interrupt for vdev config space changes.
	 */
	if(!rp_info->valid && vrp->is_bsp) {
		//rpmsg_virtio_cfg_changed(vrp);
		va = phys_to_virt(addr);
		return va;
	}

	BUG_ON(addr < rp_info->pa_start);
	BUG_ON(addr > rp_info->pa_end);

	offset = addr - rp_info->pa_start;
	va = rp_info->va_start + offset;

	BUG_ON(va + len > rp_info->va_end);

	return (void *)va;
}

void __rpmsg_pool_check(struct pool_info *p_info, void *va, size_t len)
{
	unsigned long phy_addr;

	BUG_ON(!va);
	BUG_ON(!p_info);
	BUG_ON(va < p_info->va_start || (va + len) > p_info->va_end);
	phy_addr = __pa(va);
	BUG_ON(phy_addr < p_info->pa_start || (phy_addr + len) > p_info->pa_end);
}

void __rpmsg_update_pool_info(struct pool_info *p_info, void *va,
						unsigned long addr, size_t size)
{
	p_info->pa_start = addr;
	p_info->va_start = (unsigned long)va;
	p_info->pool_size = size;
	p_info->pa_end = p_info->pa_start + size;
	p_info->va_end = p_info->va_start + size;
	p_info->valid = true;		//TODO Atomic opr
}

int rpmsg_map_fixed_buf_pool(struct virtproc_info *vrp, size_t total_buf_space)
{
	struct virtio_device *vdev = vrp->vdev;
	struct fw_rsc_vdev_buf_desc desc;
	unsigned offset;
	void *bufs_va;

	memset(&desc, 0, sizeof(struct fw_rsc_vdev_buf_desc));

	if(vrp->is_bsp) {
		offset = offsetof(struct fw_rsc_vdev_config, lproc_desc);
		vdev->config->get(vdev, offset, (void *)&desc,
				 sizeof(struct fw_rsc_vdev_buf_desc));
	} else {
		offset = offsetof(struct fw_rsc_vdev_config, rproc_desc);
		vdev->config->get(vdev, offset, (void *)&desc,
				 sizeof(struct fw_rsc_vdev_buf_desc));
	}

	dev_info(&vrp->vdev->dev, "%s: bsp %d desc.addr %p"
				" len %u (%zu)\n",__func__, vrp->is_bsp,
				(void *)desc.addr, desc.len, total_buf_space);

	if(unlikely(!desc.addr || !desc.len))
		return -1U;

	BUG_ON(desc.len != total_buf_space);

	bufs_va = ioremap_cache(desc.addr, desc.len);
	if(!bufs_va) {
		dev_err(&vrp->vdev->dev, "%s: ioremap_cache failed! phy %p"
				" len %u\n",__func__, (void *)desc.addr,
				desc.len);
		return -1U;
	}

	dev_info(&vrp->vdev->dev, "%s: ioremap_cache sucess! phy %p virt %p"
			" len %u\n",__func__, (void *)desc.addr, bufs_va,
			desc.len);

	__rpmsg_update_pool_info(&vrp->rp_info, bufs_va, desc.addr, desc.len);
	return 0;
}

/*
 * Copy recv buffer address for the remote processor
 */
void rpmsg_cfg_update_pool_info(struct virtproc_info *vrp, unsigned len)
{
	struct virtio_device *vdev = vrp->vdev;
	struct fw_rsc_vdev_buf_desc desc;
	unsigned offset;

	desc.addr = (unsigned long)vrp->vbufs_dma;
	desc.len = len;

	BUG_ON(desc.addr == 0);

	if(vrp->is_bsp) {
		offset = offsetof(struct fw_rsc_vdev_config, rproc_desc);
		vdev->config->set(vdev, offset, (void *)&desc,
				 sizeof(struct fw_rsc_vdev_buf_desc));
	} else {
		offset = offsetof(struct fw_rsc_vdev_config, lproc_desc);
		vdev->config->set(vdev, offset, (void *)&desc,
				 sizeof(struct fw_rsc_vdev_buf_desc));
	}
	dev_info(&vrp->vdev->dev,"%s: bsp %d fixed size rx pool phy %p len %u\n",
			__func__, vrp->is_bsp, (void *) desc.addr, desc.len);
}

/*
 * TODO
 * Currently we don't have a way in rpmsg virtio bus to receive notifications
 * for the config space updates. So, the virtio bus has to be improved at a
 * later phase and should be capable of invoking this routine from vdev driver.
 */
void rpmsg_virtio_cfg_changed(struct virtproc_info *vrp)
{
	queue_work(rpmsg_virtio_cfg_wq, &vrp->config_work);
}

void rpmsg_virtio_cfg_changed_work(struct work_struct *work)
{
	struct virtproc_info *vrp =
		container_of(work, struct virtproc_info, config_work);
	int ret;
	int total_buf_size;

	if(vrp->pool)
		total_buf_size = vrp->pool_size;
	else
		total_buf_size = vrp->num_bufs * RPMSG_BUF_SIZE;

	ret = rpmsg_map_fixed_buf_pool(vrp, total_buf_size);
	if (ret < 0)
		dev_err(&vrp->vdev->dev, "rpmsg remote buffer mapping failed\n");
}

int rpmsg_phy_to_virt_iov(struct virtproc_info *vrp, struct iovec piov[],
				struct iovec viov[], int iov_size, bool ptov)
{
	int i;
	struct device *dev = &vrp->vdev->dev;
	resource_size_t phy;
	__kernel_size_t len;

	for(i = 0; i < iov_size; i++) {
		if(!piov[i].iov_base)
			break;
		phy = (resource_size_t)piov[i].iov_base;
		len = (__kernel_size_t)piov[i].iov_len;
		viov[i].iov_base = ptov ? phys_to_virt(phy) :
						ioremap_cache(phy, len);
		if(!viov[i].iov_base || viov[i].iov_base < 0) {
			dev_err(dev, "%s failed on piov[%d] %p len=%u\n",
					(ptov ? "phys_to_virt" :
					"ioremap_cache"), i, (void *)phy,
					(unsigned int)len);
			return -1U;
		}
		viov[i].iov_len = piov[i].iov_len;
		dev_info(dev, "%s success piov[%d]=%p viov[%d]=%p len=%u\n",
				(ptov ? "phys_to_virt" :"ioremap_cache"),
				i, piov[i].iov_base, i, viov[i].iov_base,
				(unsigned int)piov[i].iov_len);
	}
	return i;
}

int rpmsg_iounmap_iov(struct iovec iov[], int iov_size, bool ptov)
{
	int i;
	for(i = 0; i < iov_size; i++) {
		if(!iov[i].iov_base)
			break;
		if(!ptov)
			iounmap(iov[i].iov_base);
		else
			continue;
	}
	return i;
}

void __debug_dump_rpmsg_req(struct virtproc_info *vrp, struct rpmsg_req *req,
				struct scatterlist *sg, int out, int in,
				struct iovec iov[],int iov_count)
{
	struct device *dev = &vrp->vdev->dev;
	int i;

	if(req) {
		dev_info(dev, "usd=%p usl=%d ksd=%p ksl=%d\n",req->usend.data,
				req->usend.len, req->ksend.data, req->ksend.len);
		dev_info(dev, "urd=%p url=%d krd=%p krl=%d\n",req->urecv.data,
				req->urecv.len, req->krecv.data, req->krecv.len);
	}
	if(sg) {
		dev_info(dev, "sg=%p in=%d out=%d\n", sg, in, out);
		for(i = 0; i < out; i++) {
			dev_info(dev, "out sg[%d].page_link=%p\n", i,
					(void *)sg[i].page_link);
			dev_info(dev, "out sg[%d].offset=%u\n", i, sg[i].offset);
			dev_info(dev, "out sg[%d].length=%u\n", i, sg[i].length);
		}
		for(; i < out + in; i++) {
			dev_info(dev, "in sg[%d].page_link=%p\n", i,
					(void *)(sg[i].page_link));
			dev_info(dev, "in sg[%d].offset=%u\n", i, sg[i].offset);
			dev_info(dev, "in sg[%d].length=%u\n", i, sg[i].length);
		}
	}
	if(iov) {
		for(i = 0; i < iov_count; i++){
			dev_info(dev, "iov=%p iov[%d]=%p len=%d\n",&iov[i], i,
					iov[i].iov_base,(int) iov[i].iov_len);
			}
		}
}

static struct rpmsg_hdr *rpmsg_copy_to_user(struct rpmsg_req *req, int len)
{
	struct rpmsg_hdr *kmsg = req->krecv.data;

	BUG_ON(len != req->krecv.len);
	BUG_ON(len != req->urecv.len + sizeof(struct rpmsg_hdr));
	BUG_ON(req->src != kmsg->dst);
	BUG_ON(req->dst != kmsg->src);

	memcpy(req->urecv.data, kmsg->data, kmsg->len);
	return kmsg;
}

static struct rpmsg_hdr *rpmsg_copy_from_user(struct rpmsg_req *req)
{
	struct rpmsg_hdr *msg = req->ksend.data;

	msg->len = req->ksend.len;
	msg->flags = 0;
	msg->src = req->src;
	msg->dst = req->dst;
	msg->reserved = 0;
	memcpy(msg->data, req->usend.data, req->usend.len);
	return msg;
}

/* How many bytes left in this page. */
static unsigned int rest_of_page(void *data)
{
	return PAGE_SIZE - ((unsigned long)data % PAGE_SIZE);
}

/**
 * rpmsg_pack_sg_list - pack a scatter gather list from a linear buffer
 * @sg: scatter/gather list to pack into
 * @start: which segment of the sg_list to start at
 * @limit: maximum segment to pack data to
 * @data: data to pack into scatter/gather list
 * @count: amount of data to pack into the scatter/gather list
 *
 * sg_lists have multiple segments of various sizes.  This will pack
 * arbitrary data into an existing scatter gather list, segmenting the
 * data as necessary within constraints.
 *
 * Stolen function from 9p Virtio driver.
 */

int rpmsg_pack_sg_list(struct scatterlist *sg, int start,
			int limit, char *data, int count)
{
	int s;
	int index = start;

	while (count) {
		s = rest_of_page(data);
		if (s > count)
			s = count;
		BUG_ON(index > limit);
		/* Make sure we don't terminate early. */
		sg_unmark_end(&sg[index]);
		sg_set_buf(&sg[index++], data, s);
		count -= s;
		data += s;
	}
	if (index-start)
		sg_mark_end(&sg[index - 1]);
	return index-start;
}

static void rpmsg_free_buf(void *data, unsigned char ptype)
{
	kfree(data);
}

static void *rpmsg_get_buf(unsigned size, unsigned char ptype)
{
	void *data = 0;

	data = kzalloc(size, GFP_KERNEL);
	if(!data)
		return NULL;

	return data;
}

static void rpmsg_release_request(struct rpmsg_req *req)
{
	rpmsg_free_buf(req->krecv.data, req->ptype);
	rpmsg_free_buf(req->ksend.data, req->ptype);
	kfree(req);
}

struct rpmsg_req *rpmsg_alloc_var_size_request(struct virtproc_info *vrp,
		void *sdata, int slen, void *rdata, int rlen,
		u32 src, u32 dst)
{
	struct rpmsg_req *req;
	unsigned char ptype = 0;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	req->priv = vrp;
	req->src = src;
	req->dst = dst;
	req->usend.len = slen;
	req->usend.data = sdata;
	req->urecv.len = rlen;
	req->urecv.data = rdata;

	req->ksend.data = rpmsg_get_buf(slen + sizeof(struct rpmsg_hdr), ptype);
	if(!req->ksend.data) {
		dev_err(&vrp->vdev->dev, "Variable size ksend alloc failed\n");
		goto free_request;
	}
	req->ksend.len = slen + sizeof(struct rpmsg_hdr);
	req->krecv.data = rpmsg_get_buf(rlen + sizeof(struct rpmsg_hdr), ptype);
	if(!req->krecv.data) {
		dev_err(&vrp->vdev->dev, "Variable size krecv alloc failed\n");
		goto free_ksend;
	}
	req->krecv.len = rlen + sizeof(struct rpmsg_hdr);
	sg_init_table(req->sg, RPMSG_VAR_VIRTQUEUE_NUM);

	return req;

free_ksend:
	rpmsg_free_buf(req->ksend.data, ptype);
free_request:
	kfree(req);

	return req;
}

/*
 * TODO
 * 1. Add code for input validation.
 * 2. Support for send alone, ie. rdata and rlen are NULL & 0
 */
int rpmsg_send_recv_raw(struct rpmsg_channel *rpdev, u32 src,
			u32 dst, void *sdata, int slen,
			void *rdata, int rlen, bool wait)
{
	struct virtproc_info *vrp = rpdev->vrp;
	struct device *dev = &rpdev->dev;
	struct scatterlist *sgs[2];
	struct rpmsg_hdr *msg;
	struct rpmsg_req *req;
	int err, in, out, in_sgs=0, out_sgs=0;

	/* No support for wait and retry in case of resource unavailability */
	wait = false;

	if (src == RPMSG_ADDR_ANY || dst == RPMSG_ADDR_ANY) {
		dev_err(dev, "invalid addr (src 0x%x, dst 0x%x)\n", src, dst);
		return -EINVAL;
	}
	/* Trivially validate input */
	if (!sdata || !rdata || slen == 0 || rlen == 0 || slen > MAX_BUF_SIZE
			|| rlen > MAX_BUF_SIZE) {
		dev_err(dev, "Invalid input sdata %p rdata %p slen %d rlen %d",
				sdata, rdata, slen, rlen);
		return -EINVAL;
	}

	/* alloc buffer */
	req = rpmsg_alloc_var_size_request(vrp, sdata, slen, rdata, rlen, src,
									dst);
	if (!req)
		return -ENOMEM;

	msg = rpmsg_copy_from_user(req);

	dev_info(dev, "TX From 0x%x, To 0x%x, Len %d, Flags %d, Reserved %d\n",
					msg->src, msg->dst, msg->len,
					msg->flags, msg->reserved);
#if 0
	print_hex_dump(KERN_DEBUG, "rpmsg_virtio TX: ", DUMP_PREFIX_NONE, 16, 1,
					msg, sizeof(*msg) + msg->len, true);
#endif
	out = rpmsg_pack_sg_list(req->sg, 0, RPMSG_VAR_VIRTQUEUE_NUM,
			req->ksend.data, req->ksend.len);
	sgs[out_sgs++] = &req->sg[0];

	in = rpmsg_pack_sg_list(req->sg, out, RPMSG_VAR_VIRTQUEUE_NUM,
			req->krecv.data, req->krecv.len);
	sgs[out_sgs + in_sgs++] = &req->sg[out];

	__debug_dump_rpmsg_req(vrp, req, &req->sg[0], out_sgs, in_sgs, NULL, 0);

	mutex_lock(&vrp->tx_lock);

	/* add message to the remote processor's variable size virtqueue */
	err = virtqueue_add_sgs(vrp->vvq, sgs, out_sgs, in_sgs, req, GFP_KERNEL);
	if (err < 0) {
		dev_err(dev, "virtqueue_add_sgs failed: %d\n", err);
		goto out;
	}
	err = 0;
	/* tell the remote processor it has a pending message to read */
	virtqueue_kick(vrp->vvq);
out:
	mutex_unlock(&vrp->tx_lock);
	return err;
}
EXPORT_SYMBOL(rpmsg_send_recv_raw);

void rpmsg_var_recv_done(struct virtqueue *vvq)
{
	struct virtproc_info *vrp = vvq->vdev->priv;
	queue_work(rpmsg_virtio_rcv_wq, &vrp->var_size_recv_work);
}

int rpmsg_send_recv_single(struct virtproc_info *vrp, struct device *dev,
			     struct rpmsg_req *req, unsigned int len)
{
	struct rpmsg_endpoint *ept;
	struct rpmsg_hdr *msg;

	msg = rpmsg_copy_to_user(req, len);

	dev_info(dev, "From: 0x%x, To: 0x%x, Len: %d, Flags: %d, Reserved: %d\n",
					msg->src, msg->dst, msg->len,
					msg->flags, msg->reserved);

	if (msg->len > (len - sizeof(struct rpmsg_hdr))) {
		dev_warn(dev, "inbound msg too big: (%d, %d)\n", len, msg->len);
		return -EINVAL;
	}

	/* use the dst addr to fetch the callback of the appropriate user */
	mutex_lock(&vrp->endpoints_lock);

	ept = idr_find(&vrp->endpoints, msg->dst);

	/* let's make sure no one deallocates ept while we use it */
	if (ept)
		kref_get(&ept->refcount);

	mutex_unlock(&vrp->endpoints_lock);

	if (ept) {
		/* make sure ept->cb doesn't go away while we use it */
		mutex_lock(&ept->cb_lock);

		if (ept->cb)
			ept->cb(ept->rpdev, req->urecv.data, msg->len, ept->priv,
				msg->src);

		mutex_unlock(&ept->cb_lock);

		/* farewell, ept, we don't need you anymore */
		kref_put(&ept->refcount, __ept_release);
	} else
		dev_warn(dev, "msg received with no recepient\n");

	rpmsg_release_request(req);
	return 0;
}

void rpmsg_send_recv_done(struct virtproc_info *vrp)
{
	struct device *dev = &vrp->vdev->dev;
	struct virtqueue *vvq = vrp->vvq;
	struct rpmsg_req *req;
	unsigned int len, msgs_received = 0;
	int err;

	req = virtqueue_get_buf(vvq, &len);
	if (!req) {
		dev_err(dev, "uhm, incoming signal, but no used buffer ?\n");
		return;
	}

	while (req) {
		err = rpmsg_send_recv_single(vrp, dev, req, len);
		if (err)
			break;

		msgs_received++;

		req = virtqueue_get_buf(vvq, &len);
	};

	dev_dbg(dev, "Received %u variable sized messages\n", msgs_received);
}

void rpmsg_virtio_var_size_msg_work(struct work_struct *work)
{
	struct virtproc_info *vrp =
		container_of(work, struct virtproc_info, var_size_recv_work);

	if(vrp->is_bsp)
		rpmsg_send_recv_done(vrp);
	else
		rpmsg_dummy_ap_var_size_recv_work(vrp);
}
