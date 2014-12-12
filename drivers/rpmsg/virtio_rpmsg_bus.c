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

/**
 * struct virtproc_info - virtual remote processor state
 * @vdev:	the virtio device
 * @rvq:	rx virtqueue
 * @svq:	tx virtqueue
 * @rbufs:	kernel address of rx buffers
 * @sbufs:	kernel address of tx buffers
 * @num_bufs:	total number of buffers for rx and tx
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
	unsigned int num_bufs;
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
 * We're allocating buffers of 512 bytes each for communications. The
 * number of buffers will be computed from the number of buffers supported
 * by the vring, upto a maximum of 512 buffers (256 in each direction).
 *
 * Each buffer will have 16 bytes for the msg header and 496 bytes for
 * the payload.
 *
 * This will utilize a maximum total space of 256KB for the buffers.
 *
 * We might also want to add support for user-provided buffers in time.
 * This will allow bigger buffer size flexibility, and can also be used
 * to achieve zero-copy messaging.
 *
 * Note that these numbers are purely a decision of this driver - we
 * can change this without changing anything in the firmware of the remote
 * processor.
 */
#define MAX_RPMSG_NUM_BUFS	(512)
#define RPMSG_BUF_SIZE		(512)

/*
 * Local addresses are dynamically allocated on-demand.
 * We do not dynamically assign addresses from the low 1024 range,
 * in order to reserve that address range for predefined services.
 */
#define RPMSG_RESERVED_ADDRESSES	(1024)

/* Address 53 is reserved for advertising remote services */
#define RPMSG_NS_ADDR			(53)

/* sysfs show configuration fields */
#define rpmsg_show_attr(field, path, format_string)			\
static ssize_t								\
field##_show(struct device *dev,					\
			struct device_attribute *attr, char *buf)	\
{									\
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);		\
									\
	return sprintf(buf, format_string, rpdev->path);		\
}

/* for more info, see Documentation/ABI/testing/sysfs-bus-rpmsg */
rpmsg_show_attr(name, id.name, "%s\n");
rpmsg_show_attr(src, src, "0x%lx\n");
rpmsg_show_attr(dst, dst, "0x%lx\n");
rpmsg_show_attr(announce, announce ? "true" : "false", "%s\n");

/*
 * Unique (and free running) index for rpmsg devices.
 *
 * Yeah, we're not recycling those numbers (yet?). will be easy
 * to change if/when we want to.
 */
static unsigned int rpmsg_dev_index;

/*
 * Work queue for handling config changes in rpmsg virtio device
 */
static struct workqueue_struct *rpmsg_virtio_cfg_wq;
static struct workqueue_struct *rpmsg_virtio_rcv_wq;

/*
 * Who am I ? rpmsg running on rproc/lproc
 */
static bool is_bsp;

static ssize_t modalias_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);

	return sprintf(buf, RPMSG_DEVICE_MODALIAS_FMT "\n", rpdev->id.name);
}

static struct device_attribute rpmsg_dev_attrs[] = {
	__ATTR_RO(name),
	__ATTR_RO(modalias),
	__ATTR_RO(dst),
	__ATTR_RO(src),
	__ATTR_RO(announce),
	__ATTR_NULL
};

/* rpmsg devices and drivers are matched using the service name */
static inline int rpmsg_id_match(const struct rpmsg_channel *rpdev,
				  const struct rpmsg_device_id *id)
{
	return strncmp(id->name, rpdev->id.name, RPMSG_NAME_SIZE) == 0;
}

/* match rpmsg channel and rpmsg driver */
static int rpmsg_dev_match(struct device *dev, struct device_driver *drv)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(drv);
	const struct rpmsg_device_id *ids = rpdrv->id_table;
	unsigned int i;
	for (i = 0; ids[i].name[0]; i++)
		if (rpmsg_id_match(rpdev, &ids[i]))
			return 1;

	return 0;
}

static int rpmsg_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);

	return add_uevent_var(env, "MODALIAS=" RPMSG_DEVICE_MODALIAS_FMT,
					rpdev->id.name);
}

/**
 * __ept_release() - deallocate an rpmsg endpoint
 * @kref: the ept's reference count
 *
 * This function deallocates an ept, and is invoked when its @kref refcount
 * drops to zero.
 *
 * Never invoke this function directly!
 */
static void __ept_release(struct kref *kref)
{
	struct rpmsg_endpoint *ept = container_of(kref, struct rpmsg_endpoint,
						  refcount);
	/*
	 * At this point no one holds a reference to ept anymore,
	 * so we can directly free it
	 */
	kfree(ept);
}

/* for more info, see below documentation of rpmsg_create_ept() */
static struct rpmsg_endpoint *__rpmsg_create_ept(struct virtproc_info *vrp,
		struct rpmsg_channel *rpdev, rpmsg_rx_cb_t cb,
		void *priv, unsigned long addr)
{
	int id_min, id_max, id;
	struct rpmsg_endpoint *ept;
	struct device *dev = rpdev ? &rpdev->dev : &vrp->vdev->dev;

	ept = kzalloc(sizeof(*ept), GFP_KERNEL);
	if (!ept) {
		dev_err(dev, "failed to kzalloc a new ept\n");
		return NULL;
	}

	dev_dbg(dev, "%s:%s vrp %p rpdev %p priv %p addr %lu\n",
			(is_bsp ? "host" : "lproc"),__func__, vrp, rpdev,
			priv, addr);

	kref_init(&ept->refcount);
	mutex_init(&ept->cb_lock);

	ept->rpdev = rpdev;
	ept->cb = cb;
	ept->priv = priv;

	/* do we need to allocate a local address ? */
	if (addr == RPMSG_ADDR_ANY) {
		id_min = RPMSG_RESERVED_ADDRESSES;
		id_max = 0;
	} else {
		id_min = addr;
		id_max = addr + 1;
	}

	mutex_lock(&vrp->endpoints_lock);

	/* bind the endpoint to an rpmsg address (and allocate one if needed) */
	id = idr_alloc(&vrp->endpoints, ept, id_min, id_max, GFP_KERNEL);
	if (id < 0) {
		dev_err(dev, "idr_alloc failed: %d\n", id);
		goto free_ept;
	}
	ept->addr = id;

	mutex_unlock(&vrp->endpoints_lock);

	return ept;

free_ept:
	mutex_unlock(&vrp->endpoints_lock);
	kref_put(&ept->refcount, __ept_release);
	return NULL;
}

/**
 * rpmsg_create_ept() - create a new rpmsg_endpoint
 * @rpdev: rpmsg channel device
 * @cb: rx callback handler
 * @priv: private data for the driver's use
 * @addr: local rpmsg address to bind with @cb
 *
 * Every rpmsg address in the system is bound to an rx callback (so when
 * inbound messages arrive, they are dispatched by the rpmsg bus using the
 * appropriate callback handler) by means of an rpmsg_endpoint struct.
 *
 * This function allows drivers to create such an endpoint, and by that,
 * bind a callback, and possibly some private data too, to an rpmsg address
 * (either one that is known in advance, or one that will be dynamically
 * assigned for them).
 *
 * Simple rpmsg drivers need not call rpmsg_create_ept, because an endpoint
 * is already created for them when they are probed by the rpmsg bus
 * (using the rx callback provided when they registered to the rpmsg bus).
 *
 * So things should just work for simple drivers: they already have an
 * endpoint, their rx callback is bound to their rpmsg address, and when
 * relevant inbound messages arrive (i.e. messages which their dst address
 * equals to the src address of their rpmsg channel), the driver's handler
 * is invoked to process it.
 *
 * That said, more complicated drivers might do need to allocate
 * additional rpmsg addresses, and bind them to different rx callbacks.
 * To accomplish that, those drivers need to call this function.
 *
 * Drivers should provide their @rpdev channel (so the new endpoint would belong
 * to the same remote processor their channel belongs to), an rx callback
 * function, an optional private data (which is provided back when the
 * rx callback is invoked), and an address they want to bind with the
 * callback. If @addr is RPMSG_ADDR_ANY, then rpmsg_create_ept will
 * dynamically assign them an available rpmsg address (drivers should have
 * a very good reason why not to always use RPMSG_ADDR_ANY here).
 *
 * Returns a pointer to the endpoint on success, or NULL on error.
 */
struct rpmsg_endpoint *rpmsg_create_ept(struct rpmsg_channel *rpdev,
				rpmsg_rx_cb_t cb, void *priv, unsigned long addr)
{
	return __rpmsg_create_ept(rpdev->vrp, rpdev, cb, priv, addr);
}
EXPORT_SYMBOL(rpmsg_create_ept);

/**
 * __rpmsg_destroy_ept() - destroy an existing rpmsg endpoint
 * @vrp: virtproc which owns this ept
 * @ept: endpoing to destroy
 *
 * An internal function which destroy an ept without assuming it is
 * bound to an rpmsg channel. This is needed for handling the internal
 * name service endpoint, which isn't bound to an rpmsg channel.
 * See also __rpmsg_create_ept().
 */
static void
__rpmsg_destroy_ept(struct virtproc_info *vrp, struct rpmsg_endpoint *ept)
{
	/* make sure new inbound messages can't find this ept anymore */
	mutex_lock(&vrp->endpoints_lock);
	idr_remove(&vrp->endpoints, ept->addr);
	mutex_unlock(&vrp->endpoints_lock);

	/* make sure in-flight inbound messages won't invoke cb anymore */
	mutex_lock(&ept->cb_lock);
	ept->cb = NULL;
	mutex_unlock(&ept->cb_lock);

	kref_put(&ept->refcount, __ept_release);
}

/**
 * rpmsg_destroy_ept() - destroy an existing rpmsg endpoint
 * @ept: endpoing to destroy
 *
 * Should be used by drivers to destroy an rpmsg endpoint previously
 * created with rpmsg_create_ept().
 */
void rpmsg_destroy_ept(struct rpmsg_endpoint *ept)
{
	__rpmsg_destroy_ept(ept->rpdev->vrp, ept);
}
EXPORT_SYMBOL(rpmsg_destroy_ept);

/*
 * when an rpmsg driver is probed with a channel, we seamlessly create
 * it an endpoint, binding its rx callback to a unique local rpmsg
 * address.
 *
 * if we need to, we also announce about this channel to the remote
 * processor (needed in case the driver is exposing an rpmsg service).
 */
static int rpmsg_dev_probe(struct device *dev)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(rpdev->dev.driver);
	struct virtproc_info *vrp = rpdev->vrp;
	struct rpmsg_endpoint *ept;
	int err;

	ept = rpmsg_create_ept(rpdev, rpdrv->callback, NULL, rpdev->src);
	if (!ept) {
		dev_err(dev, "failed to create endpoint\n");
		err = -ENOMEM;
		goto out;
	}

	rpdev->ept = ept;
	rpdev->src = ept->addr;

	err = rpdrv->probe(rpdev);
	if (err) {
		dev_err(dev, "%s: failed: %d\n", __func__, err);
		rpmsg_destroy_ept(ept);
		goto out;
	}

	/* need to tell remote processor's name service about this channel ? */
	if (rpdev->announce &&
			virtio_has_feature(vrp->vdev, VIRTIO_RPMSG_F_NS)) {
		struct rpmsg_ns_msg nsm;

		strncpy(nsm.name, rpdev->id.name, RPMSG_NAME_SIZE);
		nsm.addr = rpdev->src;
		nsm.flags = RPMSG_NS_CREATE;

		err = rpmsg_sendto(rpdev, &nsm, sizeof(nsm), RPMSG_NS_ADDR);
		if (err)
			dev_err(dev, "failed to announce service %d\n", err);
	}

out:
	return err;
}

static int rpmsg_dev_remove(struct device *dev)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(rpdev->dev.driver);
	struct virtproc_info *vrp = rpdev->vrp;
	int err = 0;

	/* tell remote processor's name service we're removing this channel */
	if (rpdev->announce &&
			virtio_has_feature(vrp->vdev, VIRTIO_RPMSG_F_NS)) {
		struct rpmsg_ns_msg nsm;

		strncpy(nsm.name, rpdev->id.name, RPMSG_NAME_SIZE);
		nsm.addr = rpdev->src;
		nsm.flags = RPMSG_NS_DESTROY;

		err = rpmsg_sendto(rpdev, &nsm, sizeof(nsm), RPMSG_NS_ADDR);
		if (err)
			dev_err(dev, "failed to announce service %d\n", err);
	}

	rpdrv->remove(rpdev);

	rpmsg_destroy_ept(rpdev->ept);

	return err;
}

static struct bus_type rpmsg_bus = {
	.name		= "rpmsg",
	.match		= rpmsg_dev_match,
	.dev_attrs	= rpmsg_dev_attrs,
	.uevent		= rpmsg_uevent,
	.probe		= rpmsg_dev_probe,
	.remove		= rpmsg_dev_remove,
};

/**
 * register_rpmsg_driver() - register an rpmsg driver with the rpmsg bus
 * @rpdrv: pointer to a struct rpmsg_driver
 *
 * Returns 0 on success, and an appropriate error value on failure.
 */
int register_rpmsg_driver(struct rpmsg_driver *rpdrv)
{
	rpdrv->drv.bus = &rpmsg_bus;
	return driver_register(&rpdrv->drv);
}
EXPORT_SYMBOL(register_rpmsg_driver);

/**
 * unregister_rpmsg_driver() - unregister an rpmsg driver from the rpmsg bus
 * @rpdrv: pointer to a struct rpmsg_driver
 *
 * Returns 0 on success, and an appropriate error value on failure.
 */
void unregister_rpmsg_driver(struct rpmsg_driver *rpdrv)
{
	driver_unregister(&rpdrv->drv);
}
EXPORT_SYMBOL(unregister_rpmsg_driver);

static void rpmsg_release_device(struct device *dev)
{
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);

	kfree(rpdev);
}

/*
 * match an rpmsg channel with a channel info struct.
 * this is used to make sure we're not creating rpmsg devices for channels
 * that already exist.
 */
static int rpmsg_channel_match(struct device *dev, void *data)
{
	struct rpmsg_channel_info *chinfo = data;
	struct rpmsg_channel *rpdev = to_rpmsg_channel(dev);

	if (chinfo->src != RPMSG_ADDR_ANY && chinfo->src != rpdev->src)
		return 0;

	if (chinfo->dst != RPMSG_ADDR_ANY && chinfo->dst != rpdev->dst)
		return 0;

	if (strncmp(chinfo->name, rpdev->id.name, RPMSG_NAME_SIZE))
		return 0;

	/* found a match ! */
	return 1;
}

/*
 * create an rpmsg channel using its name and address info.
 * this function will be used to create both static and dynamic
 * channels.
 */
static struct rpmsg_channel *rpmsg_create_channel(struct virtproc_info *vrp,
				struct rpmsg_channel_info *chinfo)
{
	struct rpmsg_channel *rpdev;
	struct device *tmp, *dev = &vrp->vdev->dev;
	int ret;

	/* make sure a similar channel doesn't already exist */
	tmp = device_find_child(dev, chinfo, rpmsg_channel_match);
	if (tmp) {
		/* decrement the matched device's refcount back */
		put_device(tmp);
		dev_err(dev, "channel %s:%lx:%lx already exist\n",
				chinfo->name, chinfo->src, chinfo->dst);
		return NULL;
	}

	rpdev = kzalloc(sizeof(struct rpmsg_channel), GFP_KERNEL);
	if (!rpdev) {
		pr_err("kzalloc failed\n");
		return NULL;
	}

	rpdev->vrp = vrp;
	rpdev->src = chinfo->src;
	rpdev->dst = chinfo->dst;

	/*
	 * rpmsg server channels has predefined local address (for now),
	 * and their existence needs to be announced remotely
	 */
	rpdev->announce = rpdev->src != RPMSG_ADDR_ANY ? true : false;

	strncpy(rpdev->id.name, chinfo->name, RPMSG_NAME_SIZE);

	/* very simple device indexing plumbing which is enough for now */
	dev_set_name(&rpdev->dev, "rpmsg%d", rpmsg_dev_index++);

	rpdev->dev.parent = &vrp->vdev->dev;
	rpdev->dev.bus = &rpmsg_bus;
	rpdev->dev.release = rpmsg_release_device;

	ret = device_register(&rpdev->dev);
	if (ret) {
		dev_err(dev, "device_register failed: %d\n", ret);
		put_device(&rpdev->dev);
		return NULL;
	}

	return rpdev;
}

/*
 * find an existing channel using its name + address properties,
 * and destroy it
 */
static int rpmsg_destroy_channel(struct virtproc_info *vrp,
					struct rpmsg_channel_info *chinfo)
{
	struct virtio_device *vdev = vrp->vdev;
	struct device *dev;

	dev = device_find_child(&vdev->dev, chinfo, rpmsg_channel_match);
	if (!dev)
		return -EINVAL;

	device_unregister(dev);

	put_device(dev);

	return 0;
}

int rpmsg_phy_to_virt_iov(struct iovec piov[], struct iovec viov[],
				int iov_size, bool ptov)
{
	int i;

	for(i=0; i < iov_size; i++) {
		if(!piov[i].iov_base)
			break;
		viov[i].iov_base = (ptov ? phys_to_virt(piov[i].iov_base)
				: ioremap_cache(piov[i].iov_base,
					piov[i].iov_len));
		if(!viov[i].iov_base || viov[i].iov_base < 0) {
			printk(KERN_ERR "%s failed on piov[%d]=%p\n",
				(ptov ? "phys_to_virt" :"ioremap_cache"),
				i, piov[i].iov_base);
			return -1U;
		}
		viov[i].iov_len = piov[i].iov_len;
		printk(KERN_INFO "%s success piov[%d]=%p viov[%d]=%p\n",
				(ptov ? "phys_to_virt" :"ioremap_cache"),
				i, piov[i].iov_base, i, viov[i].iov_base);
	}
	return i;
}

extern int virtqueue_get_avail_buf(struct virtqueue *_vq, int *in, int *out,
		struct iovec iov[], int iov_size);
extern int virtqueue_update_used_idx(struct virtqueue *_vq, u16 used_idx, int len);
extern void __debug_virtqueue(struct virtqueue *_vq, char *fmt);

/*
 * In this version of RPMSG we follow producer/consumer model where the tx
 * always consume a buffer from the remote processor's rx ring and sends
 * down its data. So in principle, the rings are inversed between host and
* remote processor.
*
 * TODO: A better implementation.
 *
 */
static void *get_a_fixed_size_tx_buf(struct virtproc_info *vrp, u16 *idx)
{
	int in, out, ret;
	struct iovec piov[1] = { piov[0].iov_base = 0, piov[0].iov_len = 0 };
	struct iovec viov[1] = { viov[0].iov_base = 0, viov[0].iov_len = 0 };
	bool ptov = vrp->sbufs ? true : false;

	/* support multiple concurrent senders */

	*idx = virtqueue_get_avail_buf(vrp->svq, &in, &out, piov,
							ARRAY_SIZE(piov));
	if(*idx < 0) {
		printk(KERN_INFO "virtqueue_get_avail_buf failed\n");
		return NULL;
	}

	ret = rpmsg_phy_to_virt_iov(piov, viov, ARRAY_SIZE(piov), ptov);
	if(ret < 0) {
		printk(KERN_INFO "rpmsg_phy_to_virt_iov failed\n");
		return NULL;
	}
	return viov[0].iov_base;
}

/**
 * rpmsg_upref_sleepers() - enable "tx-complete" interrupts, if needed
 * @vrp: virtual remote processor state
 *
 * This function is called before a sender is blocked, waiting for
 * a tx buffer to become available.
 *
 * If we already have blocking senders, this function merely increases
 * the "sleepers" reference count, and exits.
 *
 * Otherwise, if this is the first sender to block, we also enable
 * virtio's tx callbacks, so we'd be immediately notified when a tx
 * buffer is consumed (we rely on virtio's tx callback in order
 * to wake up sleeping senders as soon as a tx buffer is used by the
 * remote processor).
 */
static void rpmsg_upref_sleepers(struct virtproc_info *vrp)
{
	/* support multiple concurrent senders */
	mutex_lock(&vrp->tx_lock);

	/* are we the first sleeping context waiting for tx buffers ? */
	if (atomic_inc_return(&vrp->sleepers) == 1)
		/* enable "tx-complete" interrupts before dozing off */
		virtqueue_enable_cb(vrp->svq);

	mutex_unlock(&vrp->tx_lock);
}

/**
 * rpmsg_downref_sleepers() - disable "tx-complete" interrupts, if needed
 * @vrp: virtual remote processor state
 *
 * This function is called after a sender, that waited for a tx buffer
 * to become available, is unblocked.
 *
 * If we still have blocking senders, this function merely decreases
 * the "sleepers" reference count, and exits.
 *
 * Otherwise, if there are no more blocking senders, we also disable
 * virtio's tx callbacks, to avoid the overhead incurred with handling
 * those (now redundant) interrupts.
 */
static void rpmsg_downref_sleepers(struct virtproc_info *vrp)
{
	/* support multiple concurrent senders */
	mutex_lock(&vrp->tx_lock);

	/* are we the last sleeping context waiting for tx buffers ? */
	if (atomic_dec_and_test(&vrp->sleepers))
		/* disable "tx-complete" interrupts */
		virtqueue_disable_cb(vrp->svq);

	mutex_unlock(&vrp->tx_lock);
}
/**
 * rpmsg_send_offchannel_raw() - send a message across to the remote processor
 * @rpdev: the rpmsg channel
 * @src: source address
 * @dst: destination address
 * @data: payload of message
 * @len: length of payload
 * @wait: indicates whether caller should block in case no TX buffers available
 *
 * This function is the base implementation for all of the rpmsg sending API.
 *
 * It will send @data of length @len to @dst, and say it's from @src. The
 * message will be sent to the remote processor which the @rpdev channel
 * belongs to.
 *
 * The message is sent using one of the TX buffers that are available for
 * communication with this remote processor.
 *
 * If @wait is true, the caller will be blocked until either a TX buffer is
 * available, or 15 seconds elapses (we don't want callers to
 * sleep indefinitely due to misbehaving remote processors), and in that
 * case -ERESTARTSYS is returned. The number '15' itself was picked
 * arbitrarily; there's little point in asking drivers to provide a timeout
 * value themselves.
 *
 * Otherwise, if @wait is false, and there are no TX buffers available,
 * the function will immediately fail, and -ENOMEM will be returned.
 *
 * Normally drivers shouldn't use this function directly; instead, drivers
 * should use the appropriate rpmsg_{try}send{to, _offchannel} API
 * (see include/linux/rpmsg.h).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
int rpmsg_send_offchannel_raw(struct rpmsg_channel *rpdev, unsigned long src, unsigned long dst,
					void *data, int len, bool wait)
{
	struct virtproc_info *vrp = rpdev->vrp;
	struct device *dev = &rpdev->dev;
	struct scatterlist sg;
	struct rpmsg_hdr *msg;
	u16 idx;
	int err;

	/* bcasting isn't allowed */
	if (src == RPMSG_ADDR_ANY || dst == RPMSG_ADDR_ANY) {
		dev_err(dev, "invalid addr (src 0x%lx, dst 0x%lx)\n", src, dst);
		return -EINVAL;
	}

	/*
	 * We currently use fixed-sized buffers, and therefore the payload
	 * length is limited.
	 *
	 * One of the possible improvements here is either to support
	 * user-provided buffers (and then we can also support zero-copy
	 * messaging), or to improve the buffer allocator, to support
	 * variable-length buffer sizes.
	 */
	if (len > RPMSG_BUF_SIZE - sizeof(struct rpmsg_hdr)) {
		dev_err(dev, "message is too big (%d)\n", len);
		return -EMSGSIZE;
	}

	/*
	 * TODO: This implementation of RPMSG has a two step transmit. So
	 * taking tx_lock outside get_a_fixed_size_tx_buf and releasing it after
	 * virtqueue_update_used_idx. Again, we shouldn't sleep for tx buffers
	 * in this version, but incase, it is not good to sleep holding lock.
	 */

	mutex_lock(&vrp->tx_lock);

	/* grab a buffer */
	msg = get_a_fixed_size_tx_buf(vrp, &idx);

	if (!msg && !wait){
		dev_err(dev, "no tx buffers\n");
		err = -ENOMEM;
		goto out;
	}
	/* no free buffer ? wait for one (but bail after 15 seconds) */
	while (!msg) {
		/* enable "tx-complete" interrupts, if not already enabled */
		rpmsg_upref_sleepers(vrp);

		/*
		 * sleep until a free buffer is available or 15 secs elapse.
		 * the timeout period is not configurable because there's
		 * little point in asking drivers to specify that.
		 * if later this happens to be required, it'd be easy to add.
		 */
		err = wait_event_interruptible_timeout(vrp->sendq,
					(msg = get_a_fixed_size_tx_buf(vrp, &idx)),
					msecs_to_jiffies(15000));

		/* disable "tx-complete" interrupts if we're the last sleeper */
		rpmsg_downref_sleepers(vrp);

		/* timeout ? */
		if (!err) {
			dev_err(dev, "timeout waiting for a tx buffer\n");
			err = -ERESTARTSYS;
			goto out;
		}
	}

	msg->len = len;
	msg->flags = 0;
	msg->src = src;
	msg->dst = dst;
	msg->reserved = 0;
	memcpy(msg->data, data, len);

	dev_info(dev, "TX From 0x%lx, To 0x%lx, Len %d, Flags %d, Reserved %d\n",
					msg->src, msg->dst, msg->len,
					msg->flags, msg->reserved);
#if 0
	print_hex_dump(KERN_DEBUG, "rpmsg_virtio TX: ", DUMP_PREFIX_NONE, 16, 1,
					msg, sizeof(*msg) + msg->len, true);
#endif
	sg_init_one(&sg, msg, sizeof(*msg) + len);

	err = virtqueue_update_used_idx(vrp->svq, idx, len + (sizeof(*msg)));
#if 0
	/* add message to the remote processor's virtqueue */
	err = virtqueue_add_outbuf(vrp->svq, &sg, 1, msg, GFP_KERNEL);
	if (err) {
		/*
		 * need to reclaim the buffer here, otherwise it's lost
		 * (memory won't leak, but rpmsg won't use it again for TX).
		 * this will wait for a buffer management overhaul.
		 */
		dev_err(dev, "virtqueue_add_outbuf failed: %d\n", err);
		goto out;
	}

	/* tell the remote processor it has a pending message to read */
	virtqueue_kick(vrp->svq);
#endif
	mutex_unlock(&vrp->tx_lock);

	/* tell the remote processor it has a pending message to read */
	virtqueue_kick(vrp->svq);
	err = 0;
out:
	mutex_unlock(&vrp->tx_lock);
	return err;
}
EXPORT_SYMBOL(rpmsg_send_offchannel_raw);

/*
 * TODO add to header and add comments
 */
#define RPMSG_VAR_VIRTQUEUE_NUM	32

struct rpmsg_var_msg {
	u32 len;
	u8 *data;
};

struct rpmsg_req {
	u8 ptype;
	void *priv;
	unsigned long src;
	unsigned long dst;
	struct rpmsg_var_msg usend;
	struct rpmsg_var_msg urecv;
	struct rpmsg_var_msg ksend;
	struct rpmsg_var_msg krecv;
	struct scatterlist sg[RPMSG_VAR_VIRTQUEUE_NUM];
};

void __debug_dump_rpmsg_req(struct virtproc_info *vrp, struct rpmsg_req *req,
				struct scatterlist *sg, int in, int out,
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
			dev_info(dev, "out sg[%d].page_link=%p\n", i, sg[i].page_link);
			dev_info(dev, "out sg[%d].offset=%u\n", i, sg[i].offset);
			dev_info(dev, "out sg[%d].length=%u\n", i, sg[i].length);
		}
		for(; i < out + in; i++){
			dev_info(dev, "in sg[%d].page_link=%p\n", i, sg[i].page_link);
			dev_info(dev, "in sg[%d].offset=%u\n", i, sg[i].offset);
			dev_info(dev, "in sg[%d].length=%u\n", i, sg[i].length);
		}
	}
	if(iov) {
		for(i = 0; i < iov_count; i++){
			dev_info(dev, "iov=%p iov[%d]=%p len=%u\n",&iov[i], i,
					iov[i].iov_base, iov[i].iov_len);
			}
		}
}

static struct rpmsg_hdr *rpmsg_copy_to_user(struct rpmsg_req *req, unsigned long len)
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
 * sg_lists have multiple segments of various sizes.  This will pack
 * arbitrary data into an existing scatter gather list, segmenting the
 * data as necessary within constraints.
 *
 * Stolen function from 9p Virtio driver.
 *
 */
static int rpmsg_pack_sg_list(struct scatterlist *sg, int start,
			int limit, char *data, int count)
{
	int s;
	int index = start;

	while (count) {
		s = rest_of_page(data);
		if (s > count)
			s = count;
		sg_set_buf(&sg[index++], data, s);
		count -= s;
		data += s;
		BUG_ON(index > limit);
	}
	return index - start;
}

void rpmsg_sg_init(struct scatterlist **sg, struct rpmsg_req *req, int *out,
			int *in)
{
	struct virtproc_info *vrp = req->priv;
	int start = 0;

	*out = rpmsg_pack_sg_list(req->sg, 0, RPMSG_VAR_VIRTQUEUE_NUM,
			req->ksend.data, req->ksend.len);

	*in = rpmsg_pack_sg_list(req->sg, *out, RPMSG_VAR_VIRTQUEUE_NUM,
			req->krecv.data, req->krecv.len);
	*sg = req->sg;
}

void rpmsg_free_buf(void *data, unsigned char ptype)
{
	kfree(data);
}

void *rpmsg_get_buf(unsigned size, unsigned char ptype)
{
	void *data = 0;

	data = kzalloc(size, GFP_KERNEL);
	if(!data)
		return NULL;

	return data;
}

void rpmsg_release_request(struct rpmsg_req *req)
{
	rpmsg_free_buf(req->krecv.data, req->ptype);
	rpmsg_free_buf(req->ksend.data, req->ptype);
	kfree(req);
}

struct rpmsg_req *rpmsg_alloc_var_size_request(struct virtproc_info *vrp,
		void *sdata, unsigned int slen, void *rdata, unsigned int rlen,
		unsigned long src, unsigned long dst)
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
	req->usend.data= sdata;
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

free_ksend: rpmsg_free_buf(req->ksend.data, ptype);
free_request: kfree(req);
}

/*
 * TODO
 * 1. Add code for input validation.
 * 2. Support for send alone, ie. rdata and rlen are NULL & 0
 */
int rpmsg_send_recv_raw(struct rpmsg_channel *rpdev, unsigned long src,
			unsigned long dst, void *sdata, unsigned int slen,
			void *rdata, unsigned int rlen, bool wait)
{
	struct virtproc_info *vrp = rpdev->vrp;
	struct device *dev = &rpdev->dev;
	struct scatterlist *sg;
	struct rpmsg_hdr *msg;
	struct rpmsg_req *req;
	int err, in, out;

	/* No support for wait and retry in case of resource unavailability */
	wait = false;

	if (src == RPMSG_ADDR_ANY || dst == RPMSG_ADDR_ANY) {
		dev_err(dev, "invalid addr (src 0x%x, dst 0x%x)\n", src, dst);
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
	print_hex_dump(KERN_DEBUG, "rpmsg_virtio TX: ", DUMP_PREFIX_NONE, 16, 1,
					msg, sizeof(*msg) + msg->len, true);

	rpmsg_sg_init(&sg, req, &out, &in);

	__debug_dump_rpmsg_req(vrp, req, sg, out, in, NULL, 0);

	mutex_lock(&vrp->tx_lock);

	/* add message to the remote processor's variable size virtqueue */
	err = virtqueue_add_buf_gfp(vrp->vvq, sg, out, in, req, GFP_KERNEL);
	if (err < 0) {
		dev_err(dev, "virtqueue_add_buf_gfp failed: %d\n", err);
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

static int rpmsg_recv_single(struct virtproc_info *vrp, struct device *dev,
			     struct rpmsg_hdr *msg, unsigned int len)
{
	struct rpmsg_endpoint *ept;
	struct scatterlist sg;
	int err;

	dev_info(dev, "From: 0x%lx, To: 0x%lx, Len: %d, Flags: %d, Reserved: %d\n",
					msg->src, msg->dst, msg->len,
					msg->flags, msg->reserved);
#if 0
	print_hex_dump(KERN_DEBUG, "rpmsg_virtio RX: ", DUMP_PREFIX_NONE, 16, 1,
					msg, sizeof(*msg) + msg->len, true);
#endif
	/*
	 * We currently use fixed-sized buffers, so trivially sanitize
	 * the reported payload length.
	 */
	if (len > RPMSG_BUF_SIZE ||
		msg->len > (len - sizeof(struct rpmsg_hdr))) {
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
			ept->cb(ept->rpdev, msg->data, msg->len, ept->priv,
				msg->src);

		mutex_unlock(&ept->cb_lock);

		/* farewell, ept, we don't need you anymore */
		kref_put(&ept->refcount, __ept_release);
	} else
		dev_warn(dev, "msg received with no recipient\n");

	/* publish the real size of the buffer */
	sg_init_one(&sg, msg, RPMSG_BUF_SIZE);

	/* add the buffer back to the remote processor's virtqueue */
	err = virtqueue_add_inbuf(vrp->rvq, &sg, 1, msg, GFP_KERNEL);
	if (err < 0) {
		dev_err(dev, "failed to add a virtqueue buffer: %d\n", err);
		return err;
	}

	WARN_ON(err < 0); /* sanity check; this can't really happen */

	return 0;
}

/* called when an rx buffer is used, and it's time to digest a message */
static void rpmsg_recv_done(struct virtqueue *rvq)
{
	struct virtproc_info *vrp = rvq->vdev->priv;
	struct device *dev = &rvq->vdev->dev;
	struct rpmsg_hdr *msg;
	unsigned int len, msgs_received = 0;
	int err;

	msg = virtqueue_get_buf(rvq, &len);
	if (!msg) {
		dev_err(dev, "uhm, incoming signal, but no used buffer ?\n");
		return;
	}

	while (msg) {
		err = rpmsg_recv_single(vrp, dev, msg, len);
		if (err)
			break;

		msgs_received++;

		msg = virtqueue_get_buf(rvq, &len);
	};

	dev_dbg(dev, "Received %u messages\n", msgs_received);

	/* tell the remote processor we added another available rx buffer */
	if (msgs_received)
		virtqueue_kick(vrp->rvq);
}

static int rpmsg_send_recv_single(struct virtproc_info *vrp, struct device *dev,
			     struct rpmsg_req *req, unsigned int len)
{
	struct rpmsg_endpoint *ept;
	struct scatterlist sg;
	struct rpmsg_hdr *msg;
	int err;

	msg = rpmsg_copy_to_user(req, len);

	dev_info(dev, "From: 0x%lx, To: 0x%lx, Len: %d, Flags: %d, Reserved: %d\n",
					msg->src, msg->dst, msg->len,
					msg->flags, msg->reserved);

	print_hex_dump(KERN_DEBUG, "rpmsg_virtio RX: ", DUMP_PREFIX_NONE, 16, 1,
					msg, sizeof(*msg) + msg->len, true);

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

static void rpmsg_send_recv_done(struct virtproc_info *vrp)
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

	/* TODO
	 * Should we tell the remote processor about our wellness ? Is it
	 * too much of hand shaking ?
	 */
}

static unsigned int rpmsg_dummy_calc_reply_len(struct iovec iov[], int iov_count)
{
	int i;
	unsigned int len;

	for(i = 0, len = 0; i < iov_count; i++)
		len += iov[i].iov_len;

	return len;
}

static int rpmsg_dummy_var_reply(struct iovec iov[], int in, int out)
{
	struct rpmsg_hdr *recv_msg = iov[0].iov_base;
	struct rpmsg_hdr *reply_msg = iov[in].iov_base;
	static int reply_cnt;
	unsigned int len;

	BUG_ON(iov[in].iov_len < sizeof(struct rpmsg_hdr));

	len = rpmsg_dummy_calc_reply_len(iov + in, out);

	reply_msg->len = len - sizeof(struct rpmsg_hdr);
	reply_msg->flags = 0;
	reply_msg->src = recv_msg->dst;
	reply_msg->dst = recv_msg->src;
	reply_msg->reserved = 0;

	(void)snprintf((char *)reply_msg->data, len, "Variable size reply %d",
			++reply_cnt);
	return len;
}

static void rpmsg_dummy_ap_var_size_recv_work(struct virtproc_info *vrp)
{
	struct device *dev = &vrp->vdev->dev;
	int in, out, ret;
	struct iovec piov[2];
	struct iovec viov[2];
	unsigned int len;
	u16 idx;

	memset(piov, 0, (sizeof(*piov) * ARRAY_SIZE(piov)));
	memset(viov, 0, (sizeof(*viov) * ARRAY_SIZE(viov)));

	idx = virtqueue_get_avail_buf(vrp->vvq, &in, &out, piov,
		       					ARRAY_SIZE(piov));
	if(idx < 0) {
		dev_err(dev, "virtqueue_get_avail_buf failed\n");
		return NULL;
	}

	ret = rpmsg_phy_to_virt_iov(piov, viov, ARRAY_SIZE(piov), false);
	if(ret < 0) {
		dev_err(dev, "rpmsg_phy_to_virt_iov failed\n");
		return;
	}

	__debug_dump_rpmsg_req(vrp, NULL, NULL, 0, 0, viov, ARRAY_SIZE(viov));
	__debug_dump_rpmsg_req(vrp, NULL, NULL, 0, 0, piov, ARRAY_SIZE(piov));

	BUG_ON(ret != out + in);
	len = rpmsg_dummy_var_reply(viov, in, out);

	ret = virtqueue_update_used_idx(vrp->vvq, idx, len);

	virtqueue_kick(vrp->vvq);
}

static void rpmsg_virtio_var_size_msg_work(struct work_struct *work)
{
	struct virtproc_info *vrp =
		container_of(work, struct virtproc_info, var_size_recv_work);

	if(is_bsp)
		rpmsg_send_recv_done(vrp);
	else
		rpmsg_dummy_ap_var_size_recv_work(vrp);
}

void rpmsg_var_recv_done(struct virtqueue *vvq)
{
	struct virtproc_info *vrp = vvq->vdev->priv;
	queue_work(rpmsg_virtio_rcv_wq, &vrp->var_size_recv_work);
}

/*
 * This is invoked whenever the remote processor completed processing
 * a TX msg we just sent it, and the buffer is put back to the used ring.
 *
 * Normally, though, we suppress this "tx complete" interrupt in order to
 * avoid the incurred overhead.
 */
static void rpmsg_xmit_done(struct virtqueue *svq)
{
	struct virtproc_info *vrp = svq->vdev->priv;

	dev_info(&svq->vdev->dev, "%s\n", __func__);

	/* wake up potential senders that are waiting for a tx buffer */
	wake_up_interruptible(&vrp->sendq);
}

/*
 * TODO
 * 1. We need to seperate rproc and lproc by cacheline size.
 * 2. Move this defenitions to remoteproc.h
 * 3. Take care of endianness.
 * 4. Write unnap routines.
 * 5. What if multiple name service messages comes from same remote processor?
 *
 */
struct fw_rsc_vdev_sbuf_desc{
	unsigned long addr;
	u32 len;
} __packed;

struct fw_rsc_vdev_config {
	struct fw_rsc_vdev_sbuf_desc rproc_desc;
	struct fw_rsc_vdev_sbuf_desc lproc_desc;
} __packed;

#define RSC_VDEV_CONFIG_SIZE	(sizeof(fw_rsc_vdev_config))

/* Map the static buffers */
static int rpmsg_map_remote_bufs(struct virtproc_info *vrp)
{
	struct virtio_device *vdev = vrp->vdev;
	struct fw_rsc_vdev_sbuf_desc desc;
	unsigned offset;
	void *va;

	BUG_ON(vrp->sbufs != 0);

	memset(&desc, 0, sizeof(struct fw_rsc_vdev_sbuf_desc));

	if(is_bsp) {
		offset = offsetof(struct fw_rsc_vdev_config, lproc_desc);
		vdev->config->get(vdev, offset, (void *)&desc,
				 sizeof(struct fw_rsc_vdev_sbuf_desc));
	} else {
		offset = offsetof(struct fw_rsc_vdev_config, rproc_desc);
		vdev->config->get(vdev, offset, (void *)&desc,
				 sizeof(struct fw_rsc_vdev_sbuf_desc));
	}

	if(unlikely(!desc.addr || !desc.len))
		return -1U;

	printk(KERN_DEBUG "%s:ioremap rpsmg fixed size buffer pool"
			" phy %p len %u\n", __func__, desc.addr, desc.len);
	va = ioremap_cache(desc.addr, desc.len);
	if(!va) {
		printk(KERN_ERR "iormap_cache failed\n");
		return -1U;
	}
	printk(KERN_DEBUG "%s:ioremap rpmsg fixed size buffer pool"
			" done virt %p len %u\n",__func__, va, desc.len);

	BUG_ON(desc.len != RPMSG_TOTAL_BUF_SPACE);
	vrp->sbufs = va;
}

/*
 * Copy recv buffer address for the remote processor
 */
static void rpmsg_setup_recv_buf(struct virtproc_info *vrp, unsigned len)
{
	struct virtio_device *vdev = vrp->vdev;
	struct fw_rsc_vdev_sbuf_desc desc;
	unsigned offset;

	desc.addr = (unsigned long)vrp->bufs_dma;
	desc.len = len;

	BUG_ON(desc.addr == 0);
	BUG_ON(desc.len != RPMSG_TOTAL_BUF_SPACE);

	if(is_bsp) {
		offset = offsetof(struct fw_rsc_vdev_config, rproc_desc);
		vdev->config->set(vdev, offset, (void *)&desc,
				 sizeof(struct fw_rsc_vdev_sbuf_desc));
	} else {
		offset = offsetof(struct fw_rsc_vdev_config, lproc_desc);
		vdev->config->set(vdev, offset, (void *)&desc,
				 sizeof(struct fw_rsc_vdev_sbuf_desc));
	}

	printk(KERN_DEBUG "%s:set rpsmg fixed size buffer pool addr"
			" phy %p len %u\n", __func__, desc.addr, desc.len);
}

/*
 * TODO
 * Currently we don't have a way in rpmsg virtio bus to receive notifications
 * for the config space updates. So, the virtio bus has to be improved at a
 * later phase and should be capable of invoking this routine from vdev driver.
 */
static void rpmsg_virtio_cfg_changed(struct virtproc_info *vrp)
{
	queue_work(rpmsg_virtio_cfg_wq, &vrp->config_work);
}

/* invoked when a name service announcement arrives */
static void rpmsg_ns_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, unsigned long src)
{
	struct rpmsg_ns_msg *msg = data;
	struct rpmsg_channel *newch;
	struct rpmsg_channel_info chinfo;
	struct virtproc_info *vrp = priv;
	struct device *dev = &vrp->vdev->dev;
	int ret;

	print_hex_dump(KERN_DEBUG, "NS announcement: ",
			DUMP_PREFIX_NONE, 16, 1,
			data, len, true);

	if (len != sizeof(*msg)) {
		dev_err(dev, "malformed ns msg (%d)\n", len);
		return;
	}

	/*
	 * the name service ept does _not_ belong to a real rpmsg channel,
	 * and is handled by the rpmsg bus itself.
	 * for sanity reasons, make sure a valid rpdev has _not_ sneaked
	 * in somehow.
	 */
	if (rpdev) {
		dev_err(dev, "anomaly: ns ept has an rpdev handle\n");
		return;
	}

	/* don't trust the remote processor for null terminating the name */
	msg->name[RPMSG_NAME_SIZE - 1] = '\0';

	dev_info(dev, "%sing channel %s addr 0x%lx\n",
			msg->flags & RPMSG_NS_DESTROY ? "destroy" : "creat",
			msg->name, msg->addr);

	strncpy(chinfo.name, msg->name, sizeof(chinfo.name));
	chinfo.src = RPMSG_ADDR_ANY;
	chinfo.dst = msg->addr;

	if (msg->flags & RPMSG_NS_DESTROY) {
		ret = rpmsg_destroy_channel(vrp, &chinfo);
		if (ret)
			dev_err(dev, "rpmsg_destroy_channel failed: %d\n", ret);
	} else {
		newch = rpmsg_create_channel(vrp, &chinfo);
		if (!newch)
			dev_err(dev, "rpmsg_create_channel failed\n");
		/*
		 * RMSG implementation with reversed ring logic uses two rings
		 * for the fixed size send/recv. Currently, untill unless a name
		 * service message arrives, there is no way by which we can
		 * ensure that remote processor allocated buffers for fixed size
		 * rings. In the case of homogeneous multi-kernel archituctures,
		 * the fixed buffers for rpmsg are statically allocated at device
		 * probe and virtio vring descriptors are initialized with them
		 * after find_vqs. These buffer allocations are done from cma
		 * using dma_alloc_coherent function and can be memmap-ed on
		 * remote processor virtual address space using ioremap cache.
		 * This can help in avoiding invoking ioremap cache for every
		 * rpmsg send. Later, we should revisit this approach if have a
		 * generic appraoch for fixed and variable size messages.
		 *
		 * TODO
		 * 1. This has to be modified to get invoked from virtio layer
		 * as a callback.
		 */
		rpmsg_virtio_cfg_changed(vrp);
	}
}

static struct device *rpmsg_setup_ring_attr(struct virtio_device *vdev,
		bool *is_bsp, vq_callback_t *vq_cbs[], const char *names[])
{
	struct device *parent;
	const char *dname = dev_name(vdev->dev.parent);

	if(strncmp(dname, "remoteproc", 10) == 0) {
		*is_bsp = 1;
		parent = vdev->dev.parent->parent;
		vq_cbs[0] = rpmsg_recv_done;
		vq_cbs[1] = rpmsg_xmit_done;
		vq_cbs[2] = rpmsg_var_recv_done;
		names[0] = "recv";
		names[1] = "send";
		names[2] = "var";
	} else {
		*is_bsp = 0;
		parent = vdev->dev.parent;
		vq_cbs[0] = rpmsg_xmit_done;
		vq_cbs[1] = rpmsg_recv_done;
		vq_cbs[2] = rpmsg_var_recv_done;
		names[0] = "send";
		names[1] = "recv";
		names[2] = "var";
	}
	return parent;
}

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

static void create_dummy_rpmsg_ept(struct virtproc_info *vrp)
{
	struct rpmsg_ns_msg msg;
	struct rpmsg_channel *rpdev;
	struct rpmsg_channel_info chinfo;
	struct device *dev = &vrp->vdev->dev;
	struct rpmsg_endpoint *ept = NULL;
	int ret = 0;

	memset(&msg,0,sizeof(msg));

	dev_dbg(dev,"%s: vrp %p\n",__func__,vrp);

	strncpy(msg.name,"lproc",sizeof(msg.name));

	msg.addr = 1048;	//TODO hack till we use idr to get one.
	msg.flags|= RPMSG_NS_CREATE;

	strncpy(chinfo.name, msg.name, sizeof(chinfo.name));
	chinfo.src = msg.addr;
	chinfo.dst = RPMSG_ADDR_ANY;

	rpdev = rpmsg_create_channel(vrp, &chinfo);
	if (!rpdev)
		dev_err(dev, "rpmsg_create_channel failed\n");

	ept = rpmsg_create_ept(rpdev, dummy_rpmsg_cb, NULL, rpdev->src);
	if (!ept) {
		dev_err(dev, "failed to create the ns ept\n");
	}
	ret = rpmsg_sendto(rpdev, &msg, sizeof(msg), RPMSG_NS_ADDR);
	if (ret)
		dev_err(dev, "failed to announce service %d\n", ret);

}
static void rpmsg_virtio_cfg_changed_work(struct work_struct *work)
{
	struct virtproc_info *vrp =
		container_of(work, struct virtproc_info, config_work);
	int ret;

	ret = rpmsg_map_remote_bufs(vrp);
	if (ret < 0)
		dev_err(&vrp->vdev->dev, "rpmsg remote buffer mapping failed\n");
}
static int rpmsg_probe(struct virtio_device *vdev)
{
	vq_callback_t *vq_cbs[3];
	const char *names[3];
	struct virtqueue *vqs[3];
	struct virtproc_info *vrp;
	struct device *dev_parent;
	void *bufs_va = NULL;
	int err = 0, i;
	size_t total_buf_space;
	bool is_bsp;

	vrp = kzalloc(sizeof(*vrp), GFP_KERNEL);
	if (!vrp)
		return -ENOMEM;

	vrp->vdev = vdev;

	idr_init(&vrp->endpoints);
	mutex_init(&vrp->endpoints_lock);
	mutex_init(&vrp->tx_lock);
	init_waitqueue_head(&vrp->sendq);

	dev_parent = rpmsg_setup_ring_attr(vdev, &is_bsp, vq_cbs, names);

	/* We expect three virtqueues, rx, tx and var (and in this order) */
	err = vdev->config->find_vqs(vdev, 3, vqs, vq_cbs, names);
	if (err){
		dev_err(&vdev->dev, "failed vqs creation %x\n",err);
		goto free_vrp;
	}

	vrp->rvq = vqs[(is_bsp?0:1)];
	vrp->svq = vqs[(is_bsp?1:0)];
	vrp->vvq = vqs[2];

	/* allocate coherent memory for the buffers */
	bufs_va = dma_alloc_coherent(dev_parent,
				RPMSG_TOTAL_BUF_SPACE,
				&vrp->bufs_dma, GFP_KERNEL);
	if (!bufs_va) {
		dev_err(&vdev->dev, "failed bufs_va %p\n",bufs_va);
		err = -ENOMEM;
		goto vqs_del;
	}

	dev_dbg(&vdev->dev, "buffers: va %p, dma 0x%llx\n", bufs_va,
					(unsigned long long)vrp->bufs_dma);

	/* All the buffers is dedicated for RX */
	vrp->rbufs = bufs_va;

	/* set up the receive buffers */
	for (i = 0; i < RPMSG_NUM_BUFS ; i++) {
		struct scatterlist sg;
		void *cpu_addr = vrp->rbufs + i * RPMSG_BUF_SIZE;

		sg_init_one(&sg, cpu_addr, RPMSG_BUF_SIZE);

		err = virtqueue_add_inbuf(vrp->rvq, &sg, 1, cpu_addr,
								GFP_KERNEL);
		WARN_ON(err); /* sanity check; this can't really happen */
	}
	/* suppress "tx-complete" interrupts */
	virtqueue_disable_cb(vrp->svq);

	vdev->priv = vrp;

	/* if supported by the remote processor, enable the name service */
	if (virtio_has_feature(vdev, VIRTIO_RPMSG_F_NS)) {
		/* a dedicated endpoint handles the name service msgs */
		vrp->ns_ept = __rpmsg_create_ept(vrp, NULL, rpmsg_ns_cb,
						vrp, RPMSG_NS_ADDR);
		if (!vrp->ns_ept) {
			dev_err(&vdev->dev, "failed to create the ns ept\n");
			err = -ENOMEM;
			goto free_coherent;
		}
	}

	/* tell the remote processor it can start sending messages */
	virtqueue_kick(vrp->rvq);

	__debug_virtqueue(vrp->rvq,"initial replenish & kick");

	dev_info(&vdev->dev, "rpmsg %s is online\n",((is_bsp) ? "host":"lproc"));

	rpmsg_setup_recv_buf(vrp, RPMSG_TOTAL_BUF_SPACE);

	INIT_WORK(&vrp->config_work, rpmsg_virtio_cfg_changed_work);
	INIT_WORK(&vrp->var_size_recv_work, rpmsg_virtio_var_size_msg_work);

	/* Send the initial name service message from remote processor */
	if(!is_bsp){
		err = rpmsg_map_remote_bufs(vrp);
		if (err < 0)
			dev_err(&vdev->dev,"rpmsg remote buffer mapping failed\n");
		create_dummy_rpmsg_ept(vrp);
	}
	return 0;

free_coherent:
	dma_free_coherent(dev_parent, RPMSG_TOTAL_BUF_SPACE,
					bufs_va, vrp->bufs_dma);
vqs_del:
	vdev->config->del_vqs(vrp->vdev);
free_vrp:
	kfree(vrp);
	return err;
}

static int rpmsg_remove_device(struct device *dev, void *data)
{
	device_unregister(dev);

	return 0;
}

static void rpmsg_remove(struct virtio_device *vdev)
{
	struct virtproc_info *vrp = vdev->priv;
	size_t total_buf_space = vrp->num_bufs * RPMSG_BUF_SIZE;
	int ret;

	vdev->config->reset(vdev);

	ret = device_for_each_child(&vdev->dev, NULL, rpmsg_remove_device);
	if (ret)
		dev_warn(&vdev->dev, "can't remove rpmsg device: %d\n", ret);

	if (vrp->ns_ept)
		__rpmsg_destroy_ept(vrp, vrp->ns_ept);

	idr_destroy(&vrp->endpoints);

	vdev->config->del_vqs(vrp->vdev);

	dma_free_coherent(vdev->dev.parent->parent, total_buf_space,
			  vrp->rbufs, vrp->bufs_dma);

	kfree(vrp);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_RPMSG, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_RPMSG_F_NS,
};

static struct virtio_driver virtio_ipc_driver = {
	.feature_table	= features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name	= KBUILD_MODNAME,
	.driver.owner	= THIS_MODULE,
	.id_table	= id_table,
	.probe		= rpmsg_probe,
	.remove		= rpmsg_remove,
};

static int __init rpmsg_init(void)
{
	int ret;

	rpmsg_virtio_cfg_wq = alloc_workqueue("virtio-rpmsg-cfg", 0, 0);
	if (!rpmsg_virtio_cfg_wq)
		return -ENOMEM;

	rpmsg_virtio_rcv_wq = alloc_workqueue("virtio-rpmsg-recv", 0, 0);
	if (!rpmsg_virtio_rcv_wq)
		goto free_cfg_workqueue;

	ret = bus_register(&rpmsg_bus);
	if (ret) {
		pr_err("failed to register rpmsg bus: %d\n", ret);
		goto free_rcv_workqueue;
	}

	ret = register_virtio_driver(&virtio_ipc_driver);
	if (ret) {
		pr_err("failed to register virtio driver: %d\n", ret);
		goto unregister_bus;
	}
	return ret;

unregister_bus:
	bus_unregister(&rpmsg_bus);
free_rcv_workqueue:
	destroy_workqueue(rpmsg_virtio_rcv_wq);
free_cfg_workqueue:
	destroy_workqueue(rpmsg_virtio_cfg_wq);
	return ret;
}
subsys_initcall(rpmsg_init);

static void __exit rpmsg_fini(void)
{
	destroy_workqueue(rpmsg_virtio_cfg_wq);
	destroy_workqueue(rpmsg_virtio_rcv_wq);
	unregister_virtio_driver(&virtio_ipc_driver);
	bus_unregister(&rpmsg_bus);
}
module_exit(rpmsg_fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio-based remote processor messaging bus");
MODULE_LICENSE("GPL v2");
