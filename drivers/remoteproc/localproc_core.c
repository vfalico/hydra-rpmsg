#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/remoteproc.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include "dummy_proc.h"

extern struct dummy_rproc_resourcetable dummy_remoteproc_resourcetable;
extern bool is_bsp;

static struct platform_device *localproc_device;
struct dummy_rproc_resourcetable *lrsc = &dummy_remoteproc_resourcetable;

struct lproc {
	int max_notifyid;
	struct device *dev;
	struct list_head lvdevs;
	struct resource_table *table_ptr;
	struct resource_table *cached_table;
	u32 table_csum;
};

static void lproc_virtio_notify(struct virtqueue *vq)
{
	printk(KERN_INFO "lproc:  %s: we're the AP\n", __func__);
}

irqreturn_t lproc_vq_interrupt(struct lproc *rproc, int notifyid)
{
	printk(KERN_INFO "lproc:  %s: we're the AP\n", __func__);
}
EXPORT_SYMBOL(lproc_vq_interrupt);

static void __lproc_virtio_del_vqs(struct virtio_device *vdev)
{
	printk(KERN_INFO "lproc:  %s: we're the AP\n", __func__);
}

static void lproc_virtio_del_vqs(struct virtio_device *vdev)
{
	printk(KERN_INFO "lproc:  %s: we're the AP\n", __func__);
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
static u32 lproc_virtio_get_features(struct virtio_device *vdev)
{
	printk(KERN_INFO "lproc:  %s: we're the AP\n", __func__);
}

static void lproc_virtio_finalize_features(struct virtio_device *vdev)
{
	printk(KERN_INFO "lproc:  %s: we're the AP\n", __func__);
}

static void lproc_virtio_get(struct virtio_device *vdev, unsigned offset,
							void *buf, unsigned len)
{
	printk(KERN_INFO "lproc:  %s: we're the AP\n", __func__);
}

static void lproc_virtio_set(struct virtio_device *vdev, unsigned offset,
		      const void *buf, unsigned len)
{
	printk(KERN_INFO "lproc:  %s: we're the AP\n", __func__);
}

static int lproc_virtio_find_vqs(struct virtio_device *vdev, unsigned nvqs,
		       struct virtqueue *vqs[],
		       vq_callback_t *callbacks[],
		       const char *names[])
{
	int i, ret;
#if 0
	for (i = 0; i < nvqs; i) {
		vqs[i] = rp_find_vq(vdev, i, callbacks[i], names[i]);
		if (IS_ERR(vqs[i])) {
			ret = PTR_ERR(vqs[i]);
			printk(KERN_INFO "lproc: failed find rp_find_vq\n");
		}
	}
#endif
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
	printk(KERN_INFO "lproc:  %s: we're the AP\n", __func__);
}

void lproc_remove_virtio_dev(struct rproc_vdev *rvdev)
{
	unregister_virtio_device(&rvdev->vdev);
}

int lproc_add_virtio_dev(struct lproc *lproc, struct rproc_vdev *lvdev, int id)
{
	struct device *dev = lproc->dev;
	struct virtio_device *vdev = &lvdev->vdev;
	int ret;

	vdev->id.device	= id;
	vdev->config = &lproc_virtio_config_ops;
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

	printk(KERN_INFO "lproc: vdev rsc: vring%d: da %x, qsz %d, align %d\n",
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

	printk(KERN_INFO "lproc: vdev rsc: id %d, dfeatures %x, cfg len %d, %d vrings\n",
		rsc->id, rsc->dfeatures, rsc->config_len, rsc->num_of_vrings);

	/* we currently support only two vrings per lvdev */
	if (rsc->num_of_vrings > ARRAY_SIZE(lvdev->vring)) {
		printk(KERN_INFO "lproc: too many vrings: %d\n", rsc->num_of_vrings);
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
	lvdev->rproc = (struct rproc *)lproc; // TODO: Ajo Remove the Hack

	list_add_tail(&lvdev->node, &lproc->lvdevs);

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
			printk(KERN_INFO "lproc: unsupported resource %d\n", hdr->type);
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
	int ret, tablesz = sizeof(struct dummy_rproc_resourcetable); // Ajo: Hack, get it from fw

	/* resource table */
	lproc->table_ptr = lrsc;

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
		printk(KERN_INFO "lproc: %s: kzalloc failed\n", __func__);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&lproc->lvdevs);

	lproc->dev = &pdev->dev;
	lproc_config_virtio(lproc);

	return 0;
}

static int localproc_remove(struct platform_device *pdev)
{
	struct lproc *lproc = platform_get_drvdata(pdev);

	printk(KERN_INFO "lproc: %s\n", __func__);
	kfree(lproc);
	// make sure all other kmallocs are freed..Ajo
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

static int __init localproc_init(void)
{
	int ret = 0;

	printk(KERN_INFO "lproc: %s\n", __func__);
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
