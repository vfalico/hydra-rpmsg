/*
 * Dummy Remote Processor control driver
 *
 * Copyright (C) 2014 Huawei Technologies
 *
 * Author: Paul Mundt <paul.mundt@huawei.com>
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/remoteproc.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/gfp.h>
#include <linux/smp.h>
#include <linux/pci.h>
#include <asm/bootparam.h>
#include <asm/setup.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/completion.h>

#include "dummy_proc.h"

extern struct boot_params boot_params;

char *cmdline_override = "";
module_param(cmdline_override, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cmdline_override, "kernel boot paramters to pass to the second cpu, leave blank to auto-generate");

char *cmdline_append = "";
module_param(cmdline_append, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cmdline_append, "kernel boot parameters to append to auto-generated ones");

int boot_cpu = 1;
module_param(boot_cpu, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(boot_cpu, "cpu number to boot the firmware on");

char *pci_devices_handover = "disabled";
module_param(pci_devices_handover, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pci_devices_handover, "list of pci devices to disconnect/reconnect to the kernel, in the form of 0xVENDOR_ID_HEX:0xDEVICE_ID_HEX,... . To disable PCI completly set to \"disabled\" (default).");

int boot_timeout = 5;
module_param(boot_timeout, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(boot_timeout, "up to how many seconds to wait for the AP boot (default 5).");

int serial_number = -1;
module_param(serial_number, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(serial_number, "set up serial console number to use (default - no serial output)");

static void dummy_handle_pci_handover(struct rproc *rproc, char *cmdline)
{
	char pdev_desc[14], pdev_blacklist[16*10] = "pci_dev_flags=";
	struct pci_dev *pdev = NULL, *tmp;
	int c = 0;

	pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, NULL);

	while (pdev) {
		sprintf(pdev_desc, "0x%04x:0x%04x", pdev->vendor, pdev->device);
		dev_dbg(&rproc->dev, "found %x:%x pci (searching for %s)\n", pdev->vendor, pdev->device, pdev_desc);
		if (strstr(pci_devices_handover, pdev_desc)) {
			dev_dbg(&rproc->dev, "Found, disabling...\n");
			tmp = pdev;
			pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev);
			pci_stop_and_remove_bus_device(tmp);
			continue;
		} else {
			dev_dbg(&rproc->dev, "not found, blacklisting in the new kernel\n");
			sprintf(pdev_blacklist + strlen(pdev_blacklist), "%c%s:b",
				c ? ',' : pdev_desc[0], pdev_desc + (c ? 0 : 1));
			c++;
		}

		pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev);
	}

	if (c)
		sprintf(cmdline + strlen(cmdline), " %s", pdev_blacklist);
}

static void dummy_handle_mem_regions(struct rproc *rproc, char *cmdline)
{
	struct rproc_mem_entry *carveout;
	char mem_regs_str[256] = "cma=0@0 memmap=exactmap memmap=640K@0 ";

	list_for_each_entry(carveout, &rproc->carveouts, node) {
		sprintf(mem_regs_str + strlen(mem_regs_str), "memmap=%d@0x%p ",
			carveout->len, (void *)carveout->dma);
	}

	sprintf(cmdline + strlen(cmdline), " %s", mem_regs_str);
}

DECLARE_COMPLETION(dummy_rproc_boot_completion);

static void dummy_rproc_boot_callback(void *data)
{
	struct rproc *rproc = (struct rproc *)data;

	dev_info(&rproc->dev, "got a boot confirmation from AP.\n");

	complete(&dummy_rproc_boot_completion);
}

static void dummy_rproc_kick_callback(void *data)
{
	struct rproc *rproc = (struct rproc *)data;
	dev_info(&rproc->dev, "got a kick from AP.\n");
}

static int dummy_rproc_start(struct rproc *rproc)
{
	void *kernel_start_address = (void *)rproc->bootaddr, *initrd_dma;
	dma_addr_t dma_bp, dma_str, dma_initrd;
	const struct firmware *initrd;
	struct boot_params *bp;
	char *cmdline_str, *cmdline_build_str = NULL;
	int ret = -ENOMEM;

	dev_notice(&rproc->dev, "Powering up processor %d, params \"%s\"\n",
		   boot_cpu, cmdline_override);

	bp = dma_alloc_coherent(rproc->dev.parent, sizeof(*bp), &dma_bp, GFP_KERNEL);
	if (!bp) {
		dev_err(&rproc->dev, "can't allocate cma for boot_params\n");
		return -ENOMEM;
	}

	memcpy(bp, &boot_params, sizeof(*bp));

	if (memcmp(&bp->hdr.header, "HdrS", 4) != 0) {
		dev_err(&rproc->dev, "struct boot_params is broken.\n");
		goto free_bp;
	}

	if (!*cmdline_override) {
		cmdline_build_str = kmalloc(COMMAND_LINE_SIZE, GFP_KERNEL);

		if (!cmdline_build_str) {
			dev_err(&rproc->dev, "can't allocate build string.\n");
			goto free_bp;
		}

		cmdline_override = cmdline_build_str;

		sprintf(cmdline_override,
			"lproc=%d acpi_irq_nobalance lapic_timer=1000000 debug noapic",
			boot_cpu);

		if (!strcmp(pci_devices_handover, "disabled"))
			sprintf(cmdline_override + strlen(cmdline_override), " pci=off");
		else
			dummy_handle_pci_handover(rproc, cmdline_override);

		dummy_handle_mem_regions(rproc, cmdline_override);

		if (serial_number != -1)
			sprintf(cmdline_override + strlen(cmdline_override),
				" console=ttyS%d,115200n8 earlyprintk=ttyS%d,115200n8",
				serial_number, serial_number);

		if (*cmdline_append)
			sprintf(cmdline_override + strlen(cmdline_override),
				" %s", cmdline_append);
	}


	cmdline_str = dma_alloc_coherent(rproc->dev.parent, strlen(cmdline_override),
					 &dma_str, GFP_KERNEL);
	if (!cmdline_str) {
		dev_err(&rproc->dev, "can't allocate cma for cmdline\n");
		goto free_bstr;
	}

	strcpy(cmdline_str, cmdline_override);
	bp->hdr.cmd_line_ptr = __pa(cmdline_str);

	ret = request_firmware(&initrd, "initrd", &rproc->dev);

	if (ret < 0) {
		dev_err(&rproc->dev, "request_firmware failed: %d\n", ret);
		goto free_str;
	}

	initrd_dma = dma_alloc_coherent(rproc->dev.parent, initrd->size,
					&dma_initrd, GFP_KERNEL);

	if (!initrd_dma) {
		dev_err(&rproc->dev, "failed to allocate cma for fw size %zd\n",
			initrd->size);
		ret = -ENOMEM;
		goto free_fw;
	}

	memcpy(initrd_dma, initrd->data, initrd->size);

	bp->hdr.ramdisk_image = __pa(initrd_dma);
	bp->hdr.ramdisk_size = initrd->size;

	dev_info(&rproc->dev,
		 "PAs:\n\tinitrd\t\t0x%p-0x%p (%db)\n\tcmdline\t\t0x%p-0x%p (%db)\n\tboot_params\t0x%p-0x%p (%db)\n\tkernel\t\t0x%p (fw name \"%s\")\n\tCmdline:\n\t\t%s\n\n",
		 (void *)dma_initrd, (void *)(dma_initrd + initrd->size),
		 (int)initrd->size, (void *)dma_str,
		 (void *)(dma_str + strlen(cmdline_override)),
		 (int)strlen(cmdline_override), (void *)dma_bp,
		 (void *)(dma_bp + sizeof(*bp)), (int)sizeof(*bp),
		 kernel_start_address, rproc->firmware, cmdline_str);

	kfree(cmdline_build_str);

	release_firmware(initrd);

	ret = dummy_lproc_set_bsp_callback(dummy_rproc_boot_callback, rproc);

	if (ret) {
		dev_err(&rproc->dev, "failed to register IPI callback (%d).\n", ret);
		goto free_str;
	}

	ret = dummy_lproc_boot_remote_cpu(boot_cpu, kernel_start_address, bp);

	if (ret) {
		dev_err(&rproc->dev, "failed to boot (%d).\n", ret);
		goto free_str;
	}

	ret = wait_for_completion_timeout(&dummy_rproc_boot_completion,
					  HZ * boot_timeout);

	if (!ret) {
		dev_err(&rproc->dev, "didn't get a boot confirmation from AP.\n");
		ret = -EFAULT;
		goto free_str;
	}

	ret = dummy_lproc_set_bsp_callback(dummy_rproc_kick_callback, rproc);

	if (ret)
		dev_err(&rproc->dev, "failed to set the normal BSP IPI callback, we will miss them!\n");

	return 0;

free_fw:
	release_firmware(initrd);

free_str:
	dma_free_coherent(rproc->dev.parent, strlen(cmdline_override),
			  cmdline_str, dma_str);

free_bstr:
	kfree(cmdline_build_str);

free_bp:
	dma_free_coherent(rproc->dev.parent, sizeof(*bp), bp, dma_bp);

	return ret;
}

static int dummy_rproc_stop(struct rproc *rproc)
{
	dev_notice(&rproc->dev, "Powering off remote processor\n");
	return 0;
}

static void dummy_rproc_kick(struct rproc *rproc, int vqid)
{
	dev_notice(&rproc->dev, "Kicking virtqueue id #%d via apic %s\n", vqid, apic->name);
	apic->send_IPI_mask(cpumask_of(boot_cpu), DUMMY_LPROC_VECTOR);
}

static struct rproc_ops dummy_rproc_ops = {
	.start		= dummy_rproc_start,
	.stop		= dummy_rproc_stop,
	.kick		= dummy_rproc_kick,
};

static int dummy_rproc_probe(struct platform_device *pdev)
{
	struct rproc *rproc;
	int ret;

	rproc = rproc_alloc(&pdev->dev, DRV_NAME, &dummy_rproc_ops, NULL, 0);
	if (!rproc)
		return -ENOMEM;

	pdev->dev.coherent_dma_mask = DMA_BIT_MASK(64);
	pdev->dev.dma_mask = &pdev->dev.coherent_dma_mask;

	platform_set_drvdata(pdev, rproc);

	ret = rproc_add(rproc);
	if (unlikely(ret))
		goto err;

	return 0;

err:
	rproc_put(rproc);
	platform_set_drvdata(pdev, NULL);
	return ret;
}

static int dummy_rproc_remove(struct platform_device *pdev)
{
	struct rproc *rproc = platform_get_drvdata(pdev);

	rproc_del(rproc);
	rproc_put(rproc);

	platform_set_drvdata(pdev, NULL);

	return 0;
}

static struct platform_driver dummy_rproc_driver = {
	.probe	= dummy_rproc_probe,
	.remove	= dummy_rproc_remove,
	.driver = {
		.name	= DRV_NAME,
		.owner	= THIS_MODULE,
	},
};

static struct platform_device *dummy_rproc_device;

static int __init dummy_rproc_init(void)
{
	int ret = 0;

	/*
	 * Only support one dummy device for testing
	 */
	if (unlikely(dummy_rproc_device))
		return -EEXIST;

	ret = platform_driver_register(&dummy_rproc_driver);
	if (unlikely(ret))
		return ret;


	dummy_rproc_device = platform_device_register_simple(DRV_NAME, 0,
							     NULL, 0);
	if (IS_ERR(dummy_rproc_device)) {
		platform_driver_unregister(&dummy_rproc_driver);
		ret = PTR_ERR(dummy_rproc_device);
	}

	return ret;
}

static void __exit dummy_rproc_exit(void)
{
	platform_device_unregister(dummy_rproc_device);
	platform_driver_unregister(&dummy_rproc_driver);
}

module_init(dummy_rproc_init);
module_exit(dummy_rproc_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Dummy Remote Processor control driver");
