/*
 * Virtio-based remote processor messaging bus
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 *
 * Ohad Ben-Cohen <ohad@wizery.com>
 * Brian Swetland <swetland@google.com>
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
#ifndef VIRTIO_RPMSG_H
#define VIRTIO_RPMSG_H

#define	RPMSG_MAX_IOV_SIZE	32

/**
 * struct virtproc_info - virtual remote processor state
 * @vdev:	the virtio device
 * @rvq:	rx virtqueue
 * @svq:	tx virtqueue
 * @rbufs:	kernel address of rx buffers
 * @sbufs:	kernel address of tx buffers
 * @last_sbuf:	index of last tx buffer used
 * @bufs_dma:	dma base addr of the buffers
 * @tx_lock:	protects svq, sbufs and sleepers, to allow concurrent senders.
 *		sending a message might require waking up a dozing remote
 *		processor, which involves sleeping, hence the mutex.
 * @endpoints:	idr of local endpoints, allows fast retrieval
 * @endpoints_lock: lock of the endpoints set
 * @sendq:	wait queue of sending contexts waiting for a tx buffers
 * @sleepers:	number of senders that are waiting for a tx buffer
 * @ns_ept:	the bus's name service endpoint
 * @config_work: Process context for virtio config space updates.
 *
 * This structure stores the rpmsg state of a given virtio remote processor
 * device (there might be several virtio proc devices for each physical
 * remote processor).
 */
struct virtproc_info {
	struct virtio_device *vdev;
	struct virtqueue *rvq, *svq, *vvq;
	void *rbufs, *sbufs;
	int last_sbuf;
	dma_addr_t bufs_dma;
	struct mutex tx_lock;
	struct idr endpoints;
	struct mutex endpoints_lock;
	wait_queue_head_t sendq;
	atomic_t sleepers;
	struct rpmsg_endpoint *ns_ept;
	struct work_struct config_work;
	struct work_struct var_size_recv_work;
	struct iovec piov[RPMSG_MAX_IOV_SIZE];
	struct iovec viov[RPMSG_MAX_IOV_SIZE];
};

/**
 * struct rpmsg_channel_info - internal channel info representation
 * @name: name of service
 * @src: local address
 * @dst: destination address
 */
struct rpmsg_channel_info {
	char name[RPMSG_NAME_SIZE];
	unsigned long src;
	unsigned long dst;
};

#define to_rpmsg_channel(d) container_of(d, struct rpmsg_channel, dev)
#define to_rpmsg_driver(d) container_of(d, struct rpmsg_driver, drv)

/*
 * We're allocating 512 buffers of 512 bytes for communications, and then
 * using the first 256 buffers for RX, and the last 256 buffers for TX.
 *
 * Each buffer will have 16 bytes for the msg header and 496 bytes for
 * the payload.
 *
 * This will require a total space of 256KB for the buffers.
 *
 * We might also want to add support for user-provided buffers in time.
 * This will allow bigger buffer size flexibility, and can also be used
 * to achieve zero-copy messaging.
 *
 * Note that these numbers are purely a decision of this driver - we
 * can change this without changing anything in the firmware of the remote
 * processor.
 */
#define RPMSG_NUM_BUFS		(512)
#define RPMSG_BUF_SIZE		(512)
#define RPMSG_TOTAL_BUF_SPACE	(RPMSG_NUM_BUFS * RPMSG_BUF_SIZE)

/*
 * Local addresses are dynamically allocated on-demand.
 * We do not dynamically assign addresses from the low 1024 range,
 * in order to reserve that address range for predefined services.
 */
#define RPMSG_RESERVED_ADDRESSES	(1024)

/* Address 53 is reserved for advertising remote services */
#define RPMSG_NS_ADDR			(53)

void rpmsg_virtio_cfg_changed(struct virtproc_info *vrp);
void rpmsg_setup_recv_buf(struct virtproc_info *vrp, unsigned len);
void rpmsg_virtio_cfg_changed_work(struct work_struct *work);
int rpmsg_map_remote_bufs(struct virtproc_info *vrp);

void *get_a_fixed_size_tx_buf(struct virtproc_info *vrp, u16 *idx);
struct device *rpmsg_setup_ring_attr(struct virtio_device *vdev,
		bool *is_bsp, vq_callback_t *vq_cbs[], const char *names[]);
void rpmsg_virtio_var_size_msg_work(struct work_struct *work);
void rpmsg_var_recv_done(struct virtqueue *vvq);

int rpmsg_phy_to_virt_iov(struct virtproc_info *vrp, struct iovec piov[],
				struct iovec viov[], int iov_size, bool ptov);
int rpmsg_iounmap_iov(struct iovec iov[], int iov_size, bool ptov);

/* temporary virtio host api's routines */
int virtqueue_get_avail_buf(struct virtqueue *_vq, int *out, int *in,
		struct iovec iov[], int iov_size);
void virtqueue_update_used_idx(struct virtqueue *_vq, u16 used_idx,
		int len);
void __debug_virtqueue(struct virtqueue *_vq, char *fmt);

/* dummy routines for rpmsg lproc part */
void create_dummy_channel_addr(struct rpmsg_channel_info *chinfo);
void create_dummy_rpmsg_ept(struct virtproc_info *vrp,
		struct rpmsg_channel *rpdev,
		struct rpmsg_channel_info *chinfo);
void rpmsg_dummy_ap_var_size_recv_work(struct virtproc_info *vrp);

/* routines in virtio_rpmsg_bus */
void __ept_release(struct kref *kref);


#endif /*VIRTIO_RPMSG_H*/
