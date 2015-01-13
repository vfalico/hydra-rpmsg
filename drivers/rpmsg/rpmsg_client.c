/*
 * Remote processor messaging - client module for hooking rpmsg to user space.
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
#include <asm/uaccess.h>
#include "rpmsg_client_ioctl.h"
#include "rpmsg_client.h"

/* ID allocator for RPMSG client devices */
static struct ida g_rpmsg_client_ida;
/* Class of RPMSG client devices for sysfs accessibility. */
static struct class *g_rpmsg_client_class;
/* Base device node number for rpmsg client devices */
static dev_t g_rpmsg_client_devno;

#define RPMSG_CLIENT_MAX_NUM_DEVS		256
#define RPMSG_CLIENT_DEV			"crpmsg"

static const char driver_name[] = "rpmsg_client";

/* Globals */
static struct rpmsg_client_device *rcdev;
extern void rpmsg_client_ping(struct rpmsg_client_vdev *rvdev,
		 				struct rpmsg_test_args *targs);
extern void rpmsg_client_cb(struct rpmsg_channel *rpdev, void *data, int len,
							void *priv, u32 src);
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
	return nonseekable_open(inode, f);;
}

static ssize_t
rpmsg_read(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t
rpmsg_write(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	int ret;

	if(count + sizeof(struct rpmsg_hdr) > 512)
		return -EINVAL;

	if (f->f_flags & O_NONBLOCK)
		ret = rpmsg_trysend(rpdev, (void *)buf, (int)count);
	else
		ret = rpmsg_send(rpdev, (void *)buf, (int)count);

	if(ret)
		return ret;

	return count;
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
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	void __user *argp = (void __user *)arg;
	struct rpmsg_test_args *k_targs;

	switch (cmd) {
		case RPMSG_CLIENT_TEST_IOCTL:
			k_targs = kmalloc(sizeof(*k_targs), GFP_KERNEL);
			if (!k_targs)
				return -ENOMEM;

			if (copy_from_user(k_targs, argp, sizeof(*k_targs)))
				return -EFAULT;

			rpmsg_client_ping(rvdev, k_targs);
			kfree(k_targs);
			break;
		case RPMSG_CLIENT_CREATE_EPT_IOCTL:
		{
			struct rpmsg_endpoint *ept;
			unsigned long addr;
			rpmsg_rx_cb_t cb = rpmsg_client_cb;

			if(copy_from_user(addr, argp, sizeof(addr)))
				return -EFAULT;
			ept = rpmsg_create_ept(rpdev, cb, rvdev, addr);
			if (!ept) {
				dev_err(&rpdev->dev, "failed to create ept\n");
				return -ENOMEM;
			}
			rvdev->src = addr;
			rvdev->ept = ept;
		}
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
	.write = rpmsg_write,
	.read = rpmsg_read,
	.unlocked_ioctl = rpmsg_ioctl,
	.owner = THIS_MODULE,
};

static int rpmsg_client_probe(struct rpmsg_channel *rpdev)
{
	int ret = 0;
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
	INIT_LIST_HEAD(&rcdev->recvqueue);
	init_waitqueue_head(&rcdev->recvwait);

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
	dev_info(&rpdev->dev, "rpmsg client driver is removed\n");
}

static struct rpmsg_device_id rpmsg_client_driver_id_table[] = {
	{ .name	= "lproc" },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpmsg_client_driver_id_table);

static struct rpmsg_driver rpmsg_client = {
	.drv.name	= KBUILD_MODNAME,
	.drv.owner	= THIS_MODULE,
	.id_table	= rpmsg_client_driver_id_table,
	.probe		= rpmsg_client_probe,
	.callback	= rpmsg_client_cb,
	.remove		= __devexit_p(rpmsg_client_remove),
};

static int __init rpmsg_client_init(void)
{
	int ret = 0;

	ret = alloc_chrdev_region(&g_rpmsg_client_devno, 0,
		RPMSG_CLIENT_MAX_NUM_DEVS, driver_name);
	if (ret) {
		printk(KERN_ERR "alloc_chrdev_region failed ret %d\n", ret);
		return ret;
	}
	g_rpmsg_client_class = class_create(THIS_MODULE,
						driver_name);
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
	kfree(rcdev);
	unregister_rpmsg_driver(&rpmsg_client);
}
module_exit(rpmsg_client_fini);

MODULE_DESCRIPTION("Remote processor messaging client driver");
MODULE_LICENSE("GPL v2");
