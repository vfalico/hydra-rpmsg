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
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/wait.h>
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

int rpmsg_open(struct inode *inode, struct file *f)
{
	struct rpmsg_client_vdev *rvdev;
	struct rpmsg_client_device *rcdev = container_of(inode->i_cdev,
			 struct rpmsg_client_device, cdev);

	rvdev = kzalloc(sizeof(*rvdev), GFP_KERNEL);
	if(!rvdev)
		return -ENOMEM;

	rvdev->rcdev = rcdev;
	f->private_data = rvdev;
	return nonseekable_open(inode, f);
}

static inline void rpmsg_queue(struct rpmsg_recv_blk *rblk,
						 struct list_head *queue)
{
	struct rpmsg_client_device *rcdev = container_of(queue,
					struct rpmsg_client_device, recvqueue);
	unsigned long flags;

	BUG_ON(!rcdev);
	BUG_ON(!rblk);
	spin_lock_irqsave(&rcdev->recv_spinlock, flags);
	list_add_tail(&rblk->link, &rcdev->recvqueue);
	spin_unlock_irqrestore(&rcdev->recv_spinlock, flags);
}

static inline struct rpmsg_recv_blk* rpmsg_dequeue(struct list_head *queue)
{
	struct rpmsg_client_device *rcdev = container_of(queue,
					struct rpmsg_client_device, recvqueue);
	struct rpmsg_recv_blk *rblk = NULL;
	unsigned long flags;

	BUG_ON(!rcdev);
	spin_lock_irqsave(&rcdev->recv_spinlock, flags);
	if(!list_empty(&rcdev->recvqueue)) {
			rblk = list_first_entry(&rcdev->recvqueue,
					struct rpmsg_recv_blk, link);
			list_del(&rblk->link);
	}
	spin_unlock_irqrestore(&rcdev->recv_spinlock, flags);
	return rblk;
}

static ssize_t
rpmsg_read(struct file *f, char __user *buf, size_t count, loff_t *ppos)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	struct rpmsg_client_device *rcdev = rvdev->rcdev;
	struct rpmsg_channel *rpdev = rcdev->rpdev;
	struct rpmsg_recv_blk *rblk;
	int ret, copied;

	rblk = rpmsg_dequeue(&rcdev->recvqueue);
	if (!rblk) {
		if (f->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(rcdev->recvwait,
				(rblk = rpmsg_dequeue(&rcdev->recvqueue)));
		if (ret)
			return ret;
	}

	dev_info(&rpdev->dev, "%s: %d bytes from %u ",__func__,
						rblk->len, rblk->addr);
	if(rblk->len > count) {
		dev_err(&rpdev->dev, "%s: packet too big %d > %zu\n",__func__,
							rblk->len, count);
		kfree(rblk);
		return -EMSGSIZE;
	}
	if(copy_to_user(buf, rblk->data, rblk->len)){
		dev_err(&rpdev->dev, "%s: failed to copy usr=%p ker=%p\n",
						__func__, buf, rblk->data);
		kfree(rblk);
		return -EFAULT;
	}
	copied = rblk->len;
	kfree(rblk);
	return copied;
}

static ssize_t
rpmsg_write(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	int ret;

	if (f->f_flags & O_NONBLOCK)
		ret = rpmsg_trysend(rpdev, (void *)buf, (int)count);
	else
		ret = rpmsg_send(rpdev, (void *)buf, (int)count);

	if(ret < 0)
		return -ENOMEM;

	return count;
}

int rpmsg_release(struct inode *inode, struct file *f)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;

	rpmsg_ping_status(rvdev);
	if(rvdev->ept) rpmsg_destroy_ept(rvdev->ept);
	kfree(rvdev);
	printk(KERN_INFO "%s done\n",__func__);
	return 0;
}

void rpmsg_client_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct rpmsg_recv_blk *rblk;

	dev_info(&rpdev->dev, "%s: %d bytes from 0x%x",__func__, len, src);

	rblk = kmalloc(sizeof(*rblk), GFP_ATOMIC);
	if (!rblk) {
		dev_err(&rpdev->dev, "kmalloc failed!\n");
		return;
	}
	rblk->addr = src;
	rblk->priv = priv;
	rblk->len = len;
	rblk->data = data;
	rpmsg_queue(rblk, &rcdev->recvqueue);
	wake_up_interruptible(&rcdev->recvwait);
}

void rpmsg_ept_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct rpmsg_recv_blk *rblk;

	dev_info(&rpdev->dev, "%s: %d bytes from 0x%x",__func__, len, src);

	rblk = kmalloc(sizeof(*rblk), GFP_ATOMIC);
	if (!rblk) {
		dev_err(&rpdev->dev, "kmalloc failed!\n");
		return;
	}
	rblk->addr = src;
	rblk->priv = priv;
	rblk->len = len;
	rblk->data = data;
	rpmsg_queue(rblk, &rcdev->recvqueue);
	wake_up_interruptible(&rcdev->recvwait);
}


long rpmsg_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	void __user *argp = (void __user *)arg;
	struct rpmsg_test_args *k_targs;
	int ret, done;

	switch (cmd) {
		case RPMSG_CLIENT_TEST_IOCTL:
		{
			struct rpmsg_endpoint *ept;
			unsigned int addr;
			rpmsg_rx_cb_t cb = rpmsg_ping_cb;

			k_targs = kmalloc(sizeof(*k_targs), GFP_KERNEL);
			if (!k_targs)
				return -ENOMEM;

			if (copy_from_user(k_targs, argp, sizeof(*k_targs)))
				return -EFAULT;

			addr = k_targs->ept_addr;
			ept = rpmsg_create_ept(rpdev, cb, rvdev, addr);
			if (!ept) {
				dev_err(&rpdev->dev, "failed to create ept\n");
				return -ENOMEM;
			}
			rvdev->src = addr;
			rvdev->ept = ept;
			ept->priv = rvdev;
			printk(KERN_INFO "%s create_ept ept_addr=%u ept=%p\n",
					__func__, rvdev->src, rvdev->ept);

			init_waitqueue_head(&rvdev->client_wait);

			rpmsg_client_ping(rvdev, k_targs);
			if(k_targs->wait) {
				ret = wait_event_interruptible(rvdev->client_wait,
					(done = rpmsg_ping_status(rvdev)));
				if (ret)
					return ret;
			}
			kfree(k_targs);
			break;
		}
		case RPMSG_CLIENT_CREATE_EPT_IOCTL:
		{
			struct rpmsg_endpoint *ept;
			unsigned int addr = arg;
			rpmsg_rx_cb_t cb = rpmsg_ept_cb;

			printk(KERN_INFO "%s create_ept cmd=%d ept_addr=%u\n",
					__func__, cmd, addr);

			ept = rpmsg_create_ept(rpdev, cb, rvdev, addr);
			if (!ept) {
				dev_err(&rpdev->dev, "failed to create ept\n");
				return -ENOMEM;
			}
			rvdev->src = addr;
			rvdev->ept = ept;
			ept->priv = rvdev;
			printk(KERN_INFO "%s create_ept ept_addr=%u ept=%p\n",
					__func__, rvdev->src, rvdev->ept);
			break;
		}
		case RPMSG_CLIENT_DESTROY_EPT_IOCTL:
		{
			unsigned int addr = arg;

			printk(KERN_INFO "%s delete_ept cmd=%d ept_addr=%u\n",
					__func__, cmd, addr);

			rpmsg_destroy_ept(rvdev->ept);
			rvdev->src = 0;
			rvdev->ept = NULL;
			break;
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

	dev_info(&rpdev->dev, "new channel: 0x%x -> 0x%x!\n",
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
				"to create %s%d", ret, RPMSG_CLIENT_DEV,
				rcdev->id);
		goto cdevice_create_fail;
	}
	rcdev->rpdev = rpdev;
	dev_info(&rpdev->dev, "device %s%d created!\n", RPMSG_CLIENT_DEV,
								rcdev->id);
	INIT_LIST_HEAD(&rcdev->recvqueue);
	init_waitqueue_head(&rcdev->recvwait);
	spin_lock_init(&rcdev->recv_spinlock);
	return ret;

cdevice_create_fail:
	cdev_del(&rcdev->cdev);
cdevice_init_fail:
	ida_simple_remove(&g_rpmsg_client_ida, rcdev->id);
ida_fail:
	kfree(rcdev);
	return ret;
}

static void rpmsg_client_remove(struct rpmsg_channel *rpdev)
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
	.remove		= rpmsg_client_remove,
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
