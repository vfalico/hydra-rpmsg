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
#include <linux/vringh.h>
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
#include <linux/genalloc.h>
#include "virtio_rpmsg.h"

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
rpmsg_show_attr(src, src, "0x%x\n");
rpmsg_show_attr(dst, dst, "0x%x\n");
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
struct workqueue_struct *rpmsg_virtio_cfg_wq;
struct workqueue_struct *rpmsg_virtio_rcv_wq;

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
void __ept_release(struct kref *kref)
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
		void *priv, u32 addr)
{
	int id_min, id_max, id;
	struct rpmsg_endpoint *ept;
	struct device *dev = rpdev ? &rpdev->dev : &vrp->vdev->dev;

	ept = kzalloc(sizeof(*ept), GFP_KERNEL);
	if (!ept) {
		dev_err(dev, "failed to kzalloc a new ept\n");
		return NULL;
	}

	dev_info(dev, "%s:%s vrp %p rpdev %p priv %p addr %u\n",
			(vrp->is_bsp ? "host" : "lproc"),__func__, vrp, rpdev,
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
				rpmsg_rx_cb_t cb, void *priv, u32 addr)
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
		dev_err(dev, "channel %s:%x:%x already exist\n",
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

static inline void free_tx_buf(struct virtproc_info *vrp, struct buf_info *tx_info)
{
	gen_pool_free(vrp->pool, (long unsigned int)tx_info->addr, tx_info->len);
	kfree(tx_info);
}

static unsigned short release_tx_buf(struct virtproc_info *vrp)
{
	unsigned int len;
	unsigned short count = 0;
	struct buf_info *tx_info;

	while(tx_info = virtqueue_get_buf(vrp->svq, &len)) {
		free_tx_buf(vrp, tx_info);
		count++;
	}
	return count;
}

static struct buf_info *get_var_tx_buf(struct virtproc_info *vrp, size_t len)
{
	struct buf_info *tx_info;
	unsigned short free_count = 0;
	unsigned short vring_size = virtqueue_get_vring_size(vrp->svq);

	BUG_ON(!vrp->pool);

	mutex_lock(&vrp->tx_lock);

	if(vrp->svq->num_free < vring_size >> 2) {
		free_count = release_tx_buf(vrp);
		if(!free_count && vrp->svq->num_free < 16) {
			dev_info(&vrp->vdev->dev, "%s vring_num_free %d last "
					"free_count %d\n", __func__,
					vrp->svq->num_free, free_count);
			goto retry_later;
		}
	}
	tx_info = kzalloc(sizeof(*tx_info), GFP_ATOMIC);
	if(!tx_info)
		goto retry_later;

	tx_info->addr = (void *)gen_pool_alloc(vrp->pool, len);
	if(unlikely(!tx_info->addr))
		goto pool_empty;

	tx_info->len = len;
	__rpmsg_pool_check(&vrp->lp_info, tx_info->addr, tx_info->len);

	mutex_unlock(&vrp->tx_lock);
	return tx_info;

pool_empty:
	BUG_ON(free_count > 0);
	if(!free_count)
		release_tx_buf(vrp);
	kfree(tx_info);
retry_later:
	mutex_unlock(&vrp->tx_lock);
	return NULL;
}

/* super simple buffer "allocator" that is just enough for now */
static void *get_a_tx_buf(struct virtproc_info *vrp)
{
	unsigned int len;
	void *ret;

	/* support multiple concurrent senders */
	mutex_lock(&vrp->tx_lock);

	/*
	 * either pick the next unused tx buffer
	 * (half of our buffers are used for sending messages)
	 */
	if (vrp->last_sbuf < vrp->num_bufs / 2)
		ret = vrp->sbufs + RPMSG_BUF_SIZE * vrp->last_sbuf++;
	/* or recycle a used one */
	else
		ret = virtqueue_get_buf(vrp->svq, &len);

	mutex_unlock(&vrp->tx_lock);

	return ret;
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
int rpmsg_send_offchannel_raw(struct rpmsg_channel *rpdev, u32 src, u32 dst,
					void *data, int len, bool wait)
{
	struct virtproc_info *vrp = rpdev->vrp;
	struct device *dev = &rpdev->dev;
	struct rpmsg_hdr *msg;
	struct buf_info *tx_info;
	int err = 0, out;

	/* bcasting isn't allowed */
	if (src == RPMSG_ADDR_ANY || dst == RPMSG_ADDR_ANY) {
		dev_err(dev, "invalid addr (src 0x%x, dst 0x%x)\n", src, dst);
		return -EINVAL;
	}

	/*
	 * One of the possible improvements here is to support
	 * user-provided buffers (and then we can also support zero-copy
	 * messaging)
	 * */
	if (len > MAX_BUF_SIZE - sizeof(struct rpmsg_hdr)) {
		dev_err(dev, "message is too big (%d)\n", len);
		return -EMSGSIZE;
	}

	/* grab a buffer */
	tx_info = get_var_tx_buf(vrp, len + sizeof(*msg));
	if (!tx_info && !wait)
		return -ENOMEM;
	/* no free buffer ? wait for one (but bail after 15 seconds) */
	while (!tx_info) {
		/* enable "tx-complete" interrupts, if not already enabled */
		rpmsg_upref_sleepers(vrp);

		/*
		 * sleep until a free buffer is available or 15 secs elapse.
		 * the timeout period is not configurable because there's
		 * little point in asking drivers to specify that.
		 * if later this happens to be required, it'd be easy to add.
		 */
		err = wait_event_interruptible_timeout(vrp->sendq,
					(tx_info = get_var_tx_buf(vrp, len + sizeof(*msg))),
					msecs_to_jiffies(15000));

		/* disable "tx-complete" interrupts if we're the last sleeper */
		rpmsg_downref_sleepers(vrp);

		/* timeout ? */
		if (!err) {
			dev_err(dev, "timeout waiting for a tx buffer\n");
			return -ERESTARTSYS;
		}
	}

	msg = tx_info->addr;
	msg->len = len;
	msg->flags = 0;
	msg->src = src;
	msg->dst = dst;
	msg->reserved = 0;
	memcpy(msg->data, data, len);

	dev_info(dev, "TX From 0x%x, To 0x%x, Len %d, Flags %d, Reserved %d\n",
					msg->src, msg->dst, msg->len,
					msg->flags, msg->reserved);
#if 0
	print_hex_dump(KERN_DEBUG, "rpmsg_virtio TX: ", DUMP_PREFIX_NONE, 16, 1,
					msg, sizeof(*msg) + msg->len, true);
#endif
	sg_init_table(tx_info->sg, RPMSG_VAR_VIRTQUEUE_NUM);
	out = rpmsg_pack_sg_list(tx_info->sg, 0, RPMSG_VAR_VIRTQUEUE_NUM,
					(char *)msg, sizeof(*msg) + len);
	mutex_lock(&vrp->tx_lock);

	/* add message to the remote processor's virtqueue */
	err = virtqueue_add_outbuf(vrp->svq, tx_info->sg, out, tx_info, GFP_KERNEL);
	if (err) {
		/*
		 * need to reclaim the buffer here, otherwise it's lost
		 * (memory won't leak, but rpmsg won't use it again for TX).
		 * this will wait for a buffer management overhaul.
		 */
		dev_err(dev, "virtqueue_add_outbuf failed: %d\n", err);
		BUG_ON(err == -ENOMEM);
		goto out;
	}
	/* tell the remote processor it has a pending message to read */
	virtqueue_kick(vrp->svq);
out:
	mutex_unlock(&vrp->tx_lock);
	return err;
}
EXPORT_SYMBOL(rpmsg_send_offchannel_raw);

int rpmsg_recv_single(struct virtproc_info *vrp, struct device *dev,
			     struct rpmsg_hdr *msg, unsigned int len)
{
	struct rpmsg_endpoint *ept;
	struct scatterlist sg;
	int err;

#if 0
	dev_info(dev, "From: 0x%lx, To: 0x%lx, Len: %d, Flags: %d, Reserved: %d\n",
					msg->src, msg->dst, msg->len,
					msg->flags, msg->reserved);
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

	dev_info(&svq->vdev->dev, "%s vq: %s\n", __func__, svq->name);

	/* wake up potential senders that are waiting for a tx buffer */
	wake_up_interruptible(&vrp->sendq);
}

/* invoked when a name service announcement arrives */
static void rpmsg_ns_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
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

	dev_info(dev, "%sing channel %s addr 0x%x\n",
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
	}
}

int rpmsg_recv_single_vrh(struct virtproc_info *vrp, struct device *dev,
						struct vringh_kiov *riov)
{
	struct rpmsg_endpoint *ept;
	struct rpmsg_hdr *msg = msg;
	void *data;
	size_t len, dlen = 0;
	int err = 0;

	BUG_ON(riov->i == riov->used);
	BUG_ON(riov->i != 0);

	do {
		len = riov->iov[riov->i].iov_len;
		data = __rpmsg_ptov(vrp,
				(unsigned long)riov->iov[riov->i].iov_base, len);

		if(riov->i == 0) {
			msg = data;
			data = msg->data;
			len -= sizeof(struct rpmsg_hdr);
			dlen = msg->len;
		}
		dev_info(dev, "From: 0x%x, To: 0x%x, Len: %zu, Flags: %d, Reserved: %d\n",
					msg->src, msg->dst, len,
					msg->flags, msg->reserved);
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
				ept->cb(ept->rpdev, data, len, ept->priv,
						msg->src);
			mutex_unlock(&ept->cb_lock);

			/* farewell, ept, we don't need you anymore */
			kref_put(&ept->refcount, __ept_release);
		} else {
			dev_warn(dev, "%s msg received with no recipient\n",
					__func__);
			err++;
		}
		++riov->i;
		dlen -= len;
	} while(riov->i != riov->used);

	BUG_ON(dlen != 0);

	return err;
}

void rpmsg_vrh_recv_done(struct virtio_device *vdev, struct vringh *vrh)
{
	struct virtproc_info *vrp = vdev->priv;
	struct device *dev = &vdev->dev;
	struct vringh_kiov *riov = &vrp->vrh_ctx.riov;
	unsigned int msgs_received = 0, msgs_dropped = 0;
	int err;

	do {
		if(riov->i == riov->used) {
			dev_info(dev, "riov.i %d riov.used %d ctx.head %d\n",
					riov->i, riov->used, vrp->vrh_ctx.head);
			if(vrp->vrh_ctx.head != USHRT_MAX){
				vringh_complete_kern(vrp->vrh,
						vrp->vrh_ctx.head,
						0);
				vrp->vrh_ctx.head = USHRT_MAX;
			}
			err = vringh_getdesc_kern(vrp->vrh, riov, NULL,
					&vrp->vrh_ctx.head, GFP_ATOMIC);
			if (err <= 0)
				goto exit;
		}
		err = rpmsg_recv_single_vrh(vrp, dev, riov);
		if (err){
			msgs_dropped++;
			continue;
		}
		msgs_received++;
		if(msgs_received >= (vrp->vrh->vring.num >> 2))
			break;
	} while(true);
exit:
	switch(err) {
		case 0:
			dev_info(dev, "Received %u messages, dropped %u messages\n",
						msgs_received, msgs_dropped);
			BUG_ON(msgs_dropped > 0);
			break;
		case -ENOMEM:
			dev_info(dev, "vringh_getdesc_kern failed with no mem\n");
			break;
		default:
			dev_info(dev, "vringh_getdesc_kern unkown failure\n");
			break;
	}
	if (msgs_received && vringh_need_notify_kern(vrp->vrh) > 0)
		vringh_notify(vrp->vrh);
}

static void rpmsg_destroy_genpool(struct virtproc_info *vrp)
{
	dma_free_coherent(vrp->pdev, vrp->pool_size, vrp->bufs_va, vrp->vbufs_dma);
	if(!vrp->pool)
		return;
	gen_pool_destroy(vrp->pool);
	vrp->pool = NULL;
}

static int rpmsg_create_genpool(struct virtproc_info *vrp)
{
	int ret = 0;

	vrp->num_bufs = virtqueue_get_vring_size(vrp->svq);
	vrp->pool_size = vrp->num_bufs * PAGE_SIZE;
	vrp->bufs_va = dma_alloc_coherent(vrp->pdev, vrp->pool_size,
						&vrp->vbufs_dma, GFP_KERNEL);
	if (!vrp->bufs_va) {
		dev_err(&vrp->vdev->dev, "failed to alloc buf pool %p\n",
								vrp->bufs_va);
		ret = -ENOMEM;
		return ret;
	}

	vrp->pool = gen_pool_create(6, -1);
	if(!vrp->pool) {
		dev_err(&vrp->vdev->dev, "failed to create gen pool");
		ret = -ENOMEM;
		goto err;
	}
	ret = gen_pool_add_virt(vrp->pool, (unsigned long)vrp->bufs_va,
				(phys_addr_t)(virt_to_phys(vrp->bufs_va)),
				vrp->pool_size, -1);
	if(ret)
		goto err;

	return ret;

err:
	rpmsg_destroy_genpool(vrp);
	return ret;
}

static int rpmsg_find_vqs(struct virtproc_info *vrp, struct device **pdev)
{
	vq_callback_t *vq_cbs[2];
	vrh_callback_t *vrh_cbs[1];
	const char *names[2] = {"send", "var"};
	struct virtqueue *vqs[2];
	struct virtio_device *vdev = vrp->vdev;
	const char *dname = dev_name(vdev->dev.parent);
	int err;

	if(strncmp(dname, "remoteproc", 10) == 0) {
		vrp->is_bsp = true;
		*pdev = vdev->dev.parent->parent;
	} else {
		vrp->is_bsp = false;
		*pdev = vdev->dev.parent;
	}
	vrh_cbs[0] = rpmsg_vrh_recv_done;
	err = vdev->vringh_config->find_vrhs(vdev, 1, &vrp->vrh, vrh_cbs);
	if (err){
		dev_err(&vdev->dev, "failed vrh creation %x\n",err);
		return err;
	}
	vq_cbs[0] = rpmsg_xmit_done;
	vq_cbs[1] = rpmsg_var_recv_done;
	err = vdev->config->find_vqs(vdev, 2, vqs, vq_cbs, names);
	if (err){
		dev_err(&vdev->dev, "failed vqs creation %x\n",err);
		return err;
	}
	vrp->svq = vqs[0];
	vrp->vvq = vqs[1];

	return 0;
}

static void *__rpmsg_alloc_pages(struct device *dev, size_t size,
				     u64 *dma_addr, gfp_t flag)
{
	unsigned long order = get_order(size);
	unsigned long page = __get_free_pages(flag, order);

	if (page == 0UL)
		return NULL;
	memset((char *)page, 0, PAGE_SIZE << order);
	*dma_addr = __pa(page);

	return (void *) page;
}

static int rpmsg_probe(struct virtio_device *vdev)
{
	struct virtproc_info *vrp;
	void *bufs_va = NULL;
	int err = 0;
	size_t total_buf_space;

	vrp = kzalloc(sizeof(*vrp), GFP_KERNEL);
	if (!vrp)
		return -ENOMEM;

	vrp->vdev = vdev;

	idr_init(&vrp->endpoints);
	mutex_init(&vrp->endpoints_lock);
	mutex_init(&vrp->tx_lock);
	init_waitqueue_head(&vrp->sendq);

	err = rpmsg_find_vqs(vrp, &vrp->pdev);
	if (err){
		dev_err(&vdev->dev, "failed vqs creation %x\n",err);
		goto free_vrp;
	}

	/* we need less buffers if vrings are small */
	if (virtqueue_get_vring_size(vrp->svq) < MAX_RPMSG_NUM_BUFS / 2)
		vrp->num_bufs = virtqueue_get_vring_size(vrp->svq) * 2;
	else
		vrp->num_bufs = MAX_RPMSG_NUM_BUFS;
#if 0
	total_buf_space = vrp->num_bufs * RPMSG_BUF_SIZE;

	dev_info(&vdev->dev, "vring_size svq %d vvq %d vrh %d num_bufs %d total_buf_space %zu\n",
			virtqueue_get_vring_size(vrp->svq),
			virtqueue_get_vring_size(vrp->vvq),
			vrp->vrh->vring.num, vrp->num_bufs, total_buf_space);

	/* allocate coherent memory for the buffers */
	bufs_va = dma_alloc_coherent(vrp->pdev, total_buf_space, &vrp->bufs_dma,
								GFP_KERNEL);
	if (!bufs_va) {
		dev_err(&vdev->dev, "failed bufs_va %p\n",bufs_va);
		err = -ENOMEM;
		goto vqs_del;
	}

	dev_info(&vdev->dev, "buffers: va %p, dma 0x%llx\n", bufs_va,
				(unsigned long long)vrp->bufs_dma);

	/* half the buffers is dedicated for RX */
	vrp->rbufs = bufs_va;

	/* and half is dedicated for TX */
	vrp->sbufs = bufs_va + total_buf_space / 2;
#endif
	err = rpmsg_create_genpool(vrp);
	if (err){
		dev_err(&vdev->dev, "failed var size pool creation %x\n",err);
		goto free_coherent;
	}

	dev_info(&vdev->dev, "vring_size svq %d vvq %d vrh %d num_bufs %d total_buf_space %zu\n",
			virtqueue_get_vring_size(vrp->svq),
			virtqueue_get_vring_size(vrp->vvq),
			vrp->vrh->vring.num, vrp->num_bufs, vrp->pool_size);

	dev_info(&vdev->dev, "buffers: va %p, dma 0x%lx\n", vrp->bufs_va,
				(unsigned long)vrp->vbufs_dma);

	rpmsg_cfg_update_pool_info(vrp, vrp->pool_size);

	__rpmsg_update_pool_info(&vrp->lp_info, vrp->bufs_va,
				(unsigned long )vrp->vbufs_dma, vrp->pool_size);

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

	vringh_kiov_init(&vrp->vrh_ctx.riov, NULL, 0);
	vrp->vrh_ctx.head = USHRT_MAX;
#if 0
	INIT_WORK(&vrp->config_work, rpmsg_virtio_cfg_changed_work);
	INIT_WORK(&vrp->var_size_recv_work, rpmsg_virtio_var_size_msg_work);
#endif
	/* Send the initial name service message from remote processor */
	if(!vrp->is_bsp){
		struct rpmsg_channel *rpdev;
		struct rpmsg_channel_info chinfo;

		err = rpmsg_map_fixed_buf_pool(vrp, vrp->pool_size);
		if(err < 0)
			dev_err(&vrp->vdev->dev, "rpmsg remote buffer mapping failed\n");
#if 0
		create_dummy_channel_addr(&chinfo);

		rpdev = rpmsg_create_channel(vrp, &chinfo);
		if (!rpdev)
			dev_err(&vdev->dev, "rpmsg_create_channel failed\n");

		create_dummy_rpmsg_ept(vrp, rpdev, &chinfo);
#endif
	}

	dev_info(&vdev->dev, "rpmsg %s is online\n",(vrp->is_bsp ?
							"host":"lproc"));
	return 0;

free_coherent:
#if 0
	dma_free_coherent(vrp->pdev, total_buf_space, bufs_va,
				vrp->bufs_dma);
#endif
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
#if 0
	size_t total_buf_space = vrp->num_bufs * RPMSG_BUF_SIZE;
#endif
	int ret;

	vdev->config->reset(vdev);

	ret = device_for_each_child(&vdev->dev, NULL, rpmsg_remove_device);
	if (ret)
		dev_warn(&vdev->dev, "can't remove rpmsg device: %d\n", ret);

	if (vrp->ns_ept)
		__rpmsg_destroy_ept(vrp, vrp->ns_ept);

	idr_destroy(&vrp->endpoints);

	vdev->config->del_vqs(vrp->vdev);
#if 0
	dma_free_coherent(vrp->pdev, total_buf_space, vrp->rbufs, vrp->bufs_dma);
#endif
	rpmsg_destroy_genpool(vrp);

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
	int ret = 0;
#if 0
	rpmsg_virtio_cfg_wq = alloc_workqueue("virtio-rpmsg-cfg", 0, 0);
	if (!rpmsg_virtio_cfg_wq)
		return -ENOMEM;

	rpmsg_virtio_rcv_wq = alloc_workqueue("virtio-rpmsg-recv", 0, 0);
	if (!rpmsg_virtio_rcv_wq)
		goto free_cfg_workqueue;
#endif
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
#if 0
	destroy_workqueue(rpmsg_virtio_rcv_wq);
free_cfg_workqueue:
	destroy_workqueue(rpmsg_virtio_cfg_wq);
#endif
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
