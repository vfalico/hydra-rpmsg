#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/remoteproc.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_ring.h>
#include <asm/cacheflush.h>
#include "dummy_proc.h"

extern struct dummy_rproc_resourcetable dummy_remoteproc_resourcetable;
extern bool is_bsp;
extern int dummy_lproc_set_ap_callback(void (*fn)(void *), void *data);

static struct platform_device *localproc_device;
struct dummy_rproc_resourcetable *lrsc = &dummy_remoteproc_resourcetable;

struct lproc {
	int max_notifyid;
	struct device *dev;
	struct list_head lvdevs;
	struct resource_table *table_ptr;
	struct resource_table *cached_table;
	void *priv;
	u32 table_csum;
	u64 intr_count;
};
extern void dummy_lproc_kick_bsp(void);

static bool lproc_virtio_notify(struct virtqueue *vq)
{
	/*
	 * TODO: We currently don't have anything implemented to
	 * kick the right queue on the other end. For time being
	 * ISR will look for work in both queues.
	 */
	dummy_lproc_kick_bsp();
	return true;
}
/* kick the remote processor, and let it know which vring to poke at */
static void lproc_virtio_vringh_notify(struct vringh *vrh)
{
#if 0
	struct rproc_vring *lvring = vringh_to_rvring(vrh);
	struct lproc *lproc;
	int notifyid;

	lproc = (struct lproc *)lvring->rvdev->rproc;
	notifyid = lvring->notifyid;
#endif
	dummy_lproc_kick_bsp();
}


static void lproc_virtio_del_vqs(struct virtio_device *vdev)
{
	printk(KERN_INFO "%s: Not implemented\n", __func__);
}

static u8 lproc_virtio_get_status(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)lproc->table_ptr + lvdev->rsc_offset;

	return rsc->status;
}

static void lproc_virtio_set_status(struct virtio_device *vdev, u8 status)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)lproc->table_ptr + lvdev->rsc_offset;

	rsc->status = status;
	dev_dbg(&vdev->dev, "status: %d\n", status);

}

static void lproc_virtio_reset(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)lproc->table_ptr + lvdev->rsc_offset;

	rsc->status = 0;
	dev_dbg(&vdev->dev, "reset !\n");

}

/* provide the vdev features as retrieved from the firmware */
static u64 lproc_virtio_get_features(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)lproc->table_ptr + lvdev->rsc_offset;

	dev_dbg(&vdev->dev,"%s: gfeatures %x\n", __func__,rsc->gfeatures);
	return rsc->gfeatures;
}

static int lproc_virtio_finalize_features(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)lproc->table_ptr + lvdev->rsc_offset;

	vring_transport_features(vdev);

	dev_dbg(&vdev->dev,"%s:gfeatures %x dfeatures %x vdev->features %llx\n",
			__func__,rsc->gfeatures,rsc->dfeatures,vdev->features);
	return 0;
}

/* Helper function that creates and initializes the host virtio ring */
static struct vringh *lproc_create_new_vringh(struct rproc_vring *lvring,
					unsigned int index,
					vrh_callback_t callback)
{
	struct rproc_vringh *lvrh = NULL;
	struct rproc_vdev *lvdev = lvring->rvdev;
	struct virtio_device *vdev = &lvdev->vdev;
	int err;

	lvrh = kzalloc(sizeof(*lvrh), GFP_KERNEL);
	err = -ENOMEM;
	if (!lvrh)
		goto err;

	/* initialize the host virtio ring */
	lvrh->vringh_cb = callback;
	lvrh->vrh.notify = lproc_virtio_vringh_notify;
	memset(lvring->va, 0, vring_size(lvring->len, lvring->align));
	vring_init(&lvrh->vrh.vring, lvring->len, lvring->va, lvring->align);

	/*
	 * Create the new vring host, and tell we're not interested in
	 * the 'weak' smp barriers, since we're talking with a real device.
	 */
	err = vringh_init_kern(&lvrh->vrh,
				lproc_virtio_get_features(&lvdev->vdev),
				lvring->len,
				false,
				lvrh->vrh.vring.desc,
				lvrh->vrh.vring.avail,
				lvrh->vrh.vring.used);
	if (err) {
		dev_err(&vdev->dev, "vringh_init_kern failed\n");
		goto err;
	}

	lvring->rvringh = lvrh;
	lvrh->rvring = lvring;
	return &lvrh->vrh;
err:
	kfree(lvrh);
	return ERR_PTR(err);
}

static void lproc_virtio_get(struct virtio_device *vdev, unsigned offset,
							void *buf, unsigned len)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;
	void *cfg;

	rsc = (void *)lproc->table_ptr + lvdev->rsc_offset;
	cfg = &rsc->vring[rsc->num_of_vrings];

	if (offset + len > rsc->config_len || offset + len < len) {
		dev_err(&vdev->dev, "lproc_virtio_get: access out of bounds\n");
		return;
	}
	dev_info(&vdev->dev, "%s: offset %d table_ptr %p rsc %p, cfg %p\n",
			__func__, offset, lproc->table_ptr, rsc, cfg);
	memcpy(buf, cfg + offset, len);
}

static void lproc_virtio_set(struct virtio_device *vdev, unsigned offset,
		      const void *buf, unsigned len)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;
	void *cfg;

	rsc = (void *)lproc->table_ptr + lvdev->rsc_offset;
	cfg = &rsc->vring[rsc->num_of_vrings];

	if (offset + len > rsc->config_len || offset + len < len) {
		dev_err(&vdev->dev, "rproc_virtio_set: access out of bounds\n");
		return;
	}
	dev_info(&vdev->dev, "%s: offset %d table_ptr %p rsc %p, cfg %p\n",
			__func__, offset, lproc->table_ptr, rsc, cfg);
	memcpy(cfg + offset, buf, len);
}

int lproc_map_vring(struct rproc_vdev *lvdev, int i)
{
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct device *dev = lproc->dev;
	struct rproc_vring *lvring = &lvdev->vring[i];
	struct fw_rsc_vdev *rsc;
	dma_addr_t dma;
	void *va;
	int size, notifyid;

	rsc = (void *)lproc->table_ptr + lvdev->rsc_offset;
	dma = rsc->vring[i].da;
	notifyid = rsc->vring[i].notifyid;

	/* actual size of vring (in bytes) */
	size = PAGE_ALIGN(vring_size(lvring->len, lvring->align));

	va = ioremap_cache(dma, size);
	if (!va) {
		dev_err(dev, "ioremap failed\n");
		return -EINVAL;
	}

	dev_info(dev, "vring%d: va %p dma %llx size %d idr %d\n", i, va,
				(unsigned long long)dma, size, notifyid);

	lvring->va = va;
	lvring->dma = dma;
	lvring->notifyid = notifyid;
	return 0;
}

static struct virtqueue *lp_find_vq(struct virtio_device *vdev,
				    unsigned id,
				    void (*callback)(struct virtqueue *vq),
				    const char *name)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct device *dev = lproc->dev;
	struct rproc_vring *lvring;
	struct virtqueue *vq;
	void *addr;
	int len, ret, i;

	if (id >= ARRAY_SIZE(lvdev->vring))
		return ERR_PTR(-EINVAL);

	for (i = 0; i < ARRAY_SIZE(lvdev->vring); i++) {
		lvring = &lvdev->vring[i];

		/* Use vring not already in use */
		if (!lvring->rvringh && !lvring->vq)
			break;
	}

	if (i == ARRAY_SIZE(lvdev->vring))
		return ERR_PTR(-EINVAL);

	ret = lproc_map_vring(lvdev, i);
	if (ret)
		return ERR_PTR(ret);

	lvring = &lvdev->vring[i];
	addr = lvring->va;
	len = lvring->len;

	dev_info(dev, "vring%d: va %p qsz %d notifyid %d\n",
					i, addr, len, lvring->notifyid);

	/*
	 * Create the new vq, and tell virtio we're not interested in
	 * the 'weak' smp barriers, since we're talking with a real device.
	 */
	vq = vring_new_virtqueue(i, len, lvring->align, vdev, false, addr,
					lproc_virtio_notify, callback, name);
	if (!vq) {
		dev_err(dev, "vring_new_virtqueue %s failed\n", name);
#if 0
		/*
		 *TODO: Implement the cleanup features.
		 */
		lproc_free_vring(lvring);
#endif
		return ERR_PTR(-ENOMEM);
	}

	lvring->vq = vq;
	vq->priv = lvring;

	return vq;
}

extern irqreturn_t vring_avail_interrupt(int irq, void *_vq);
/*
 * TODO: Fix the following two routines to interrupt only the virtqueue which
 * has some work to do.
 */
static irqreturn_t lproc_vq_interrupt(struct lproc *lproc, int notifyid)
{
	struct rproc_vdev *lvdev;
	struct rproc_vring *lvring;
	int ret = IRQ_NONE;

	if(lproc && lproc->priv) {
		lvdev = lproc->priv;
		lvring = &lvdev->vring[notifyid];
		switch (notifyid) {
			case 0:
				ret = vring_interrupt(1, lvring->vq);
				break;
			case 1:
				if (lvring->rvringh && lvring->rvringh->vringh_cb){
					lvring->rvringh->vringh_cb(&lvring->rvdev->vdev,
							&lvring->rvringh->vrh); 
					ret = IRQ_HANDLED;
				} else {
					printk(KERN_INFO "%s: Failed interrupt!",
						"notifyid %d ", __func__,
								notifyid);
					ret = IRQ_NONE;
				}
				break;
			case 2:
				ret = vring_avail_interrupt(1, lvring->vq);
				break;
			default:
				printk(KERN_INFO "%s: Failed interrupt!",
						"notifyid %d ", __func__,
								notifyid);
				ret = IRQ_NONE;
		}
	} else
		printk(KERN_INFO "%s: Failed interrupt! lproc %p priv %p\n",
					       __func__, lproc, lproc->priv);
	return ret;
}

void dummy_lproc_callback(void *data)
{
	struct lproc *lproc = data;
	int i;

	printk(KERN_INFO "%s lproc %p\n",__func__, lproc);
	if (unlikely(!lproc)) {
		printk(KERN_DEBUG "In %s %p\n",__func__, lproc);
		return;
	}

	for (i=0; i <= lproc->max_notifyid; i++) {
		if(lproc_vq_interrupt(lproc,i) == IRQ_NONE) {
			printk(KERN_DEBUG "%s No work to do vq %d\n",__func__,i);
		}
	}
}

static int lproc_virtio_find_vqs(struct virtio_device *vdev, unsigned nvqs,
		       struct virtqueue *vqs[],
		       vq_callback_t *callbacks[],
		       const char *names[])
{
	int i, ret=0;
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;

	for (i = 0; i < nvqs; i++) {
		vqs[i] = lp_find_vq(vdev, i, callbacks[i], names[i]);
		if (IS_ERR(vqs[i])) {
			ret = PTR_ERR(vqs[i]);
			dev_dbg(&vdev->dev,"lproc: failed find rp_find_vq\n");
		}
	}

	if(dummy_lproc_set_ap_callback(dummy_lproc_callback,(void *)lproc)) {
		dev_err(&vdev->dev,"%s: registering callback for rproc "
				"interrupts failed\n",__func__);
	}

	return ret;
}

static struct virtio_config_ops lproc_virtio_config_ops = {
	.get_features	= lproc_virtio_get_features,
	.finalize_features = lproc_virtio_finalize_features,
	.find_vqs	= lproc_virtio_find_vqs,
	.del_vqs	= lproc_virtio_del_vqs,
	.reset		= lproc_virtio_reset,
	.set_status	= lproc_virtio_set_status,
	.get_status	= lproc_virtio_get_status,
	.get		= lproc_virtio_get,
	.set		= lproc_virtio_set,
};

static void lproc_vdev_release(struct device *dev)
{
	printk(KERN_INFO "%s: Not implemented yet\n", __func__);
}

void lproc_remove_virtio_dev(struct rproc_vdev *lvdev)
{
	unregister_virtio_device(&lvdev->vdev);
}

static struct vringh *lp_find_vrh(struct virtio_device *vdev,
				unsigned id,
				vrh_callback_t callback)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct lproc *lproc = (struct lproc *)lvdev->rproc;
	struct device *dev = lproc->dev;
	struct rproc_vring *lvring;
	struct vringh *vrh;
	void *addr;
	int len, size, ret, i;

	if (id >= ARRAY_SIZE(lvdev->vring))
		return ERR_PTR(-EINVAL);

	/* Find available slot for a new host vring */
	for (i = 0; i < ARRAY_SIZE(lvdev->vring); i++) {
		lvring = &lvdev->vring[i];

		/* HACK:: TODO
		 * Use vring not already in use
		 * */
		if (!lvring->vq && (i == 1) && !lvring->rvringh)
			break;
	}

	if (i == ARRAY_SIZE(lvdev->vring))
		return ERR_PTR(-ENODEV);

	ret = lproc_map_vring(lvdev, i);
	if (ret)
		return ERR_PTR(ret);

	addr = lvring->va;
	len = lvring->len;

	/* zero vring */
	size = vring_size(len, lvring->align);
	memset(addr, 0, size);

	dev_info(dev, "vringh%d: va %p qsz %d notifyid %d\n",
					i, addr, len, lvring->notifyid);

	/*
	 * Create the new vringh, and tell virtio we're not interested in
	 * the 'weak' smp barriers, since we're talking with a real device.
	 */
	vrh = lproc_create_new_vringh(lvring, i, callback);
	if (!vrh) {
		//lproc_free_vring(lvring);
		return ERR_PTR(-ENOMEM);
	}

	return vrh;
}

static void __lproc_virtio_del_vrhs(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	int i, num_of_vrings = ARRAY_SIZE(lvdev->vring);

	for (i = 0; i < num_of_vrings; i++) {
		struct rproc_vring *lvring = &lvdev->vring[i];
		if (!lvring->rvringh)
			continue;
		kfree(lvring->rvringh);
		lvring->rvringh = NULL;
		//lproc_free_vring(lvring);
	}
}

static void lproc_virtio_del_vrhs(struct virtio_device *vdev)
{
	printk(KERN_INFO "%s: Not implemented completely\n", __func__);
	__lproc_virtio_del_vrhs(vdev);
}

static int lproc_virtio_find_vrhs(struct virtio_device *vdev, unsigned nhvrs,
			 struct vringh *vrhs[],
			 vrh_callback_t *callbacks[])
{
	int i, ret;

	for (i = 0; i < nhvrs; ++i) {
		vrhs[i] = lp_find_vrh(vdev, i, callbacks[i]);
		if (IS_ERR(vrhs[i])) {
			ret = PTR_ERR(vrhs[i]);
			goto error;
		}
	}
	return 0;
error:
	__lproc_virtio_del_vrhs(vdev);
	return ret;
}

static struct vringh_config_ops lproc_virtio_vringh_ops = {
	.find_vrhs	= lproc_virtio_find_vrhs,
	.del_vrhs	= lproc_virtio_del_vrhs,
};


int lproc_add_virtio_dev(struct lproc *lproc, struct rproc_vdev *lvdev, int id)
{
	struct device *dev = lproc->dev;
	struct virtio_device *vdev = &lvdev->vdev;
	int ret;

	vdev->id.device	= id;
	vdev->config = &lproc_virtio_config_ops;
	vdev->vringh_config = &lproc_virtio_vringh_ops;
	vdev->dev.parent = dev;
	vdev->dev.release = lproc_vdev_release;

	ret = register_virtio_device(vdev);
	if (ret) {
		dev_err(dev, "lproc: failed to register vdev: %d\n", ret);
		goto out;
	}

	dev_info(dev, "registered %s (type %d)\n", dev_name(&vdev->dev), id);
out:
	return ret;
}


static int
lproc_parse_vring(struct rproc_vdev *lvdev, struct fw_rsc_vdev *rsc, int i)
{
	struct fw_rsc_vdev_vring *vring = &rsc->vring[i];
	struct rproc_vring *lvring = &lvdev->vring[i];

	printk(KERN_INFO "lproc: vdev rsc: vring%d: da %lx, qsz %d, align %d\n",
				i, vring->da, vring->num, vring->align);

	/* make sure reserved bytes are zeroes */
	if (vring->reserved) {
		printk(KERN_INFO "lproc: vring rsc has non zero reserved bytes\n");
		return -EINVAL;
	}

	/* verify queue size and vring alignment are sane */
	if (!vring->num || !vring->align) {
		printk(KERN_INFO "lproc: invalid qsz (%d) or alignment (%d)\n",
						vring->num, vring->align);
		return -EINVAL;
	}

	lvring->len = vring->num;
	lvring->align = vring->align;
	lvring->rvdev = lvdev;

	return 0;
}
static int lproc_handle_vdev(struct lproc *lproc, struct fw_rsc_vdev *rsc,
							int offset, int avail)
{
	struct rproc_vdev *lvdev;
	int i, ret;

	/* make sure resource isn't truncated */
	if (sizeof(*rsc)+ rsc->num_of_vrings * sizeof(struct fw_rsc_vdev_vring)
			+ rsc->config_len > avail) {
		printk(KERN_INFO "lproc: vdev rsc is truncated\n");
		return -EINVAL;
	}

	/* make sure reserved bytes are zeroes */
	if (rsc->reserved[0] || rsc->reserved[1]) {
		printk(KERN_INFO "lproc: vdev rsc has non zero reserved bytes\n");
		return -EINVAL;
	}

	printk(KERN_INFO "lproc: vdev rsc: id %d gfeatures %x dfeatures %x"
			"cfg len %d %dvrings\n",rsc->id, rsc->gfeatures,
			rsc->dfeatures, rsc->config_len, rsc->num_of_vrings);

	/* we currently support only two vrings per lvdev */
	if (rsc->num_of_vrings > ARRAY_SIZE(lvdev->vring)) {
		printk(KERN_INFO "lproc: too many vrings: %d\n",
				rsc->num_of_vrings);
		return -EINVAL;
	}

	lvdev = kzalloc(sizeof(struct rproc_vdev), GFP_KERNEL);
	if (!lvdev)
		return -ENOMEM;

	/* parse the vrings */
	for (i = 0; i < rsc->num_of_vrings; i++) {
		ret = lproc_parse_vring(lvdev, rsc, i);
		if (ret)
			goto free_lvdev;
	}

	/* remember the resource offset*/
	lvdev->rsc_offset = offset;
	lvdev->rproc = (struct rproc *)lproc; // TODO: Remove the Hack

	list_add_tail(&lvdev->node, &lproc->lvdevs);
	lproc->priv = lvdev;

	/* it is now safe to add the virtio device */
	ret = lproc_add_virtio_dev(lproc, lvdev, rsc->id);
	if (ret)
		goto remove_lvdev;

	return 0;
remove_lvdev:
	list_del(&lvdev->node);
free_lvdev:
	kfree(lvdev);
	return ret;
}

static int lproc_count_vrings(struct lproc *lproc, struct fw_rsc_vdev *rsc,
			      int offset, int avail)
{
	/* Summarize the number of notification IDs */
	lproc->max_notifyid += rsc->num_of_vrings;

	return 0;
}

typedef int (*lproc_handle_resource_t)(struct lproc *lproc,
				 void *, int offset, int avail);

static lproc_handle_resource_t lproc_vdev_handler[RSC_LAST] = {
	[RSC_VDEV] = (lproc_handle_resource_t)lproc_handle_vdev,
};

static lproc_handle_resource_t lproc_count_vrings_handler[RSC_LAST] = {
	[RSC_VDEV] = (lproc_handle_resource_t)lproc_count_vrings,
};

/* handle firmware resource entries before booting the remote processor */
static int lproc_handle_resources(struct lproc *lproc, int len,
				  lproc_handle_resource_t handlers[RSC_LAST])
{
	lproc_handle_resource_t handler;
	int ret = 0, i;

	for (i = 0; i < lproc->table_ptr->num; i++) {
		int offset = lproc->table_ptr->offset[i];
		struct fw_rsc_hdr *hdr = (void *)lproc->table_ptr + offset;
		int avail = len - offset - sizeof(*hdr);
		void *rsc = (void *)hdr + sizeof(*hdr);

		/* make sure table isn't truncated */
		if (avail < 0) {
			printk(KERN_INFO "lproc: rsc table is truncated\n");
			return -EINVAL;
		}

		if (hdr->type >= RSC_LAST) {
			printk(KERN_INFO "lproc: unsupported resource %d\n",
					hdr->type);
			continue;
		}

		handler = handlers[hdr->type];
		if (!handler)
			continue;

		ret = handler(lproc, rsc, offset + sizeof(*hdr), avail);
		if (ret)
			break;
	}

	return ret;
}

/*
 * Take the lproc and attach the rings to virtio devices to register
 * on the local processor.
 *
 */
static void lproc_config_virtio(struct lproc *lproc)
{
	// TODO get it from fw table routines
	int ret, tablesz = sizeof(struct dummy_rproc_resourcetable);
	/* resource table */
	lproc->table_ptr = (struct resource_table *)lrsc;

	/* count the number of notify-ids */
	lproc->max_notifyid = -1;
	ret = lproc_handle_resources(lproc, tablesz, lproc_count_vrings_handler);
	if (ret) {
		kfree(lproc->cached_table);
		return;
	}

	/* look for virtio devices and register them */
	ret = lproc_handle_resources(lproc, tablesz, lproc_vdev_handler);
}

static int localproc_probe(struct platform_device *pdev)
{
	struct lproc *lproc;

	lproc = kzalloc(sizeof(struct lproc), GFP_KERNEL);
	if (!lproc) {
		dev_dbg(&pdev->dev,"%s: kzalloc failed\n", __func__);
		return -ENOMEM;
	}

	pdev->dev.coherent_dma_mask = DMA_BIT_MASK(64);
	pdev->dev.dma_mask = &pdev->dev.coherent_dma_mask;

	INIT_LIST_HEAD(&lproc->lvdevs);

	lproc->dev = &pdev->dev;
	lproc_config_virtio(lproc);
		return 0;
}

/*
 * TODO:make sure all other kmallocs are freed.
 */
static int localproc_remove(struct platform_device *pdev)
{
	struct lproc *lproc = platform_get_drvdata(pdev);

	dev_dbg(&pdev->dev,"%s\n", __func__);
	kfree(lproc);
	platform_set_drvdata(pdev, NULL);
	return 0;
}

static struct platform_driver localproc_driver = {
	.probe	= localproc_probe,
	.remove	= localproc_remove,
	.driver = {
		.name	= LDRV_NAME,
		.owner	= THIS_MODULE,
	},
};

int __init localproc_init(void)
{
	int ret = 0;

	/*
	 * Only support one dummy device for testing
	 */
	if (unlikely(localproc_device))
		return -EEXIST;

	if(is_bsp) {
		printk(KERN_INFO "lproc: don't run on BSP. Exiting\n");
		return ret;
	}

	ret = platform_driver_register(&localproc_driver);
	if (unlikely(ret))
		return ret;

	localproc_device = platform_device_register_simple(LDRV_NAME, 0,
							     NULL, 0);
	if (IS_ERR(localproc_device)) {
		platform_driver_unregister(&localproc_driver);
		ret = PTR_ERR(localproc_device);
	}

	return ret;
}
late_initcall(localproc_init);

static void __exit localproc_exit(void)
{
	platform_device_unregister(localproc_device);
	platform_driver_unregister(&localproc_driver);
}
